#![allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use std::ffi::c_void;
use std::marker::PhantomData;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;
use std::slice;

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{E_ACCESSDENIED, VARIANT_BOOL};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IAction, IExecAction, IRegisteredTask, ITaskDefinition, ITaskFolder, ITaskService,
    TASK_ACTION_EXEC, TASK_CREATE, TASK_IGNORE_REGISTRATION_TRIGGERS, TASK_INSTANCES_IGNORE_NEW,
    TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_LUA, TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, HRESULT, Interface};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorDacl, IsValidAcl,
    IsValidSid, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

use crate::pipe::PipeEndpoint;
use crate::windows::{access_allowed_ace_size_is_exact, same_sid, well_known_sid};
use crate::{NativeError, NativeErrorCode, NativeOperation, sha256_file};

const ARGUMENTS: &str = "daemon --install-slot stable";
const EXECUTION_TIME_LIMIT: &str = "PT0S";
const OWNER_URI_PREFIX: &str = "urn:codex-agent-mesh:daemon:";
const TASK_PREFIX: &str = "CodexAgentMesh-daemon-";
const HRESULT_FILE_NOT_FOUND: HRESULT = HRESULT(0x8007_0002_u32.cast_signed());
const HRESULT_PATH_NOT_FOUND: HRESULT = HRESULT(0x8007_0003_u32.cast_signed());
const RPC_E_CHANGED_MODE: HRESULT = HRESULT(0x8001_0106_u32.cast_signed());

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledTaskSpec {
    install_id: String,
    task_name: String,
    owner_uri: String,
    user_sid: String,
    daemon_path: PathBuf,
    daemon_path_text: String,
    working_directory: PathBuf,
    working_directory_text: String,
    daemon_sha256: [u8; 32],
    expected_definition_digest: [u8; 32],
}

impl ScheduledTaskSpec {
    pub fn new(
        install_id: impl Into<String>,
        daemon_path: impl AsRef<Path>,
        expected_daemon_sha256: [u8; 32],
    ) -> Result<Self, NativeError> {
        let install_id = install_id.into();
        let endpoint = PipeEndpoint::for_current_user(&install_id)?;
        let daemon_path = std::fs::canonicalize(daemon_path)
            .map_err(|error| io_error(&error, NativeOperation::InspectTask))?;
        if !daemon_path.is_absolute() || !daemon_path.is_file() {
            return Err(invalid_task_spec());
        }
        if sha256_file(&daemon_path)? != expected_daemon_sha256 {
            return Err(NativeError::new(
                NativeErrorCode::SetupDrifted,
                NativeOperation::InspectTask,
            ));
        }
        let working_directory = daemon_path
            .parent()
            .ok_or_else(invalid_task_spec)?
            .to_path_buf();
        let daemon_path_text = daemon_path
            .to_str()
            .ok_or_else(invalid_task_spec)?
            .to_owned();
        let working_directory_text = working_directory
            .to_str()
            .ok_or_else(invalid_task_spec)?
            .to_owned();
        let scope = endpoint
            .name()
            .rsplit_once('-')
            .map(|(_, scope)| scope)
            .ok_or_else(invalid_task_spec)?;
        let task_name = format!("{TASK_PREFIX}{scope}");
        let owner_uri = format!("{OWNER_URI_PREFIX}{install_id}");
        let mut spec = Self {
            install_id,
            task_name,
            owner_uri,
            user_sid: endpoint.account_sid().to_owned(),
            daemon_path,
            daemon_path_text,
            working_directory,
            working_directory_text,
            daemon_sha256: expected_daemon_sha256,
            expected_definition_digest: [0; 32],
        };
        spec.expected_definition_digest = spec.expected_snapshot().digest()?;
        Ok(spec)
    }

    #[must_use]
    pub fn install_id(&self) -> &str {
        &self.install_id
    }

    #[must_use]
    pub fn task_name(&self) -> &str {
        &self.task_name
    }

    #[must_use]
    pub fn task_path(&self) -> String {
        format!(r"\{}", self.task_name)
    }

    #[must_use]
    pub fn owner_uri(&self) -> &str {
        &self.owner_uri
    }

    #[must_use]
    pub fn user_sid(&self) -> &str {
        &self.user_sid
    }

    #[must_use]
    pub fn daemon_path(&self) -> &Path {
        &self.daemon_path
    }

    #[must_use]
    pub fn daemon_sha256(&self) -> &[u8; 32] {
        &self.daemon_sha256
    }

    #[must_use]
    pub fn expected_definition_digest(&self) -> &[u8; 32] {
        &self.expected_definition_digest
    }

    fn expected_snapshot(&self) -> TaskDefinitionSnapshot {
        TaskDefinitionSnapshot {
            registration_uri: self.task_path(),
            owner_marker: self.owner_uri.clone(),
            user_sid: self.user_sid.clone(),
            logon_type: TASK_LOGON_INTERACTIVE_TOKEN.0,
            run_level: TASK_RUNLEVEL_LUA.0,
            trigger_count: 0,
            action_count: 1,
            action_type: TASK_ACTION_EXEC.0,
            action_path: self.daemon_path_text.clone(),
            action_arguments: ARGUMENTS.to_owned(),
            working_directory: self.working_directory_text.clone(),
            allow_demand_start: true,
            multiple_instances: TASK_INSTANCES_IGNORE_NEW.0,
            execution_time_limit: EXECUTION_TIME_LIMIT.to_owned(),
            stop_if_going_on_batteries: false,
            disallow_start_if_on_batteries: false,
            run_only_if_idle: false,
            run_only_if_network_available: false,
            enabled: true,
            restart_count: 0,
            start_when_available: false,
            security_exact: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ScheduledTaskState {
    Absent,
    Ready,
    Running,
    Disabled,
    Drifted,
    AccessDenied,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledTaskStatus {
    pub state: ScheduledTaskState,
    pub last_task_result: Option<i32>,
    pub running_instances: u32,
    pub expected_definition_digest: [u8; 32],
    pub actual_definition_digest: Option<[u8; 32]>,
}

impl ScheduledTaskStatus {
    fn absent(spec: &ScheduledTaskSpec) -> Self {
        Self {
            state: ScheduledTaskState::Absent,
            last_task_result: None,
            running_instances: 0,
            expected_definition_digest: spec.expected_definition_digest,
            actual_definition_digest: None,
        }
    }
}

#[derive(Debug)]
pub struct ScheduledTaskController {
    root: ITaskFolder,
    // Declared last so COM interfaces above are released before CoUninitialize.
    _com: ComApartment,
}

impl ScheduledTaskController {
    pub fn connect() -> Result<Self, NativeError> {
        let com = ComApartment::initialize()?;
        // SAFETY: COM is initialized on this thread; TaskScheduler is the
        // documented in-process class for ITaskService.
        let service: ITaskService = unsafe {
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| com_error(error, NativeOperation::ConnectTaskScheduler))?
        };
        let empty = VARIANT::default();
        // SAFETY: empty variants select the local service and current identity.
        unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(|error| com_error(error, NativeOperation::ConnectTaskScheduler))?;
        }
        // SAFETY: the service is connected and the root task folder is `\`.
        let root = unsafe {
            service
                .GetFolder(&BSTR::from(r"\"))
                .map_err(|error| com_error(error, NativeOperation::ConnectTaskScheduler))?
        };
        Ok(Self { root, _com: com })
    }

    pub fn status(&self, spec: &ScheduledTaskSpec) -> Result<ScheduledTaskStatus, NativeError> {
        let Some(task) = self.get_task(spec)? else {
            return Ok(ScheduledTaskStatus::absent(spec));
        };
        Self::status_of_registered(spec, &task)
    }

    pub fn setup(&self, spec: &ScheduledTaskSpec) -> Result<ScheduledTaskStatus, NativeError> {
        match self.status(spec)? {
            status
                if matches!(
                    status.state,
                    ScheduledTaskState::Ready | ScheduledTaskState::Running
                ) =>
            {
                return Ok(status);
            }
            status if status.state != ScheduledTaskState::Absent => {
                return Err(status_error(status.state, NativeOperation::SetupTask));
            }
            _ => {}
        }
        let definition = Self::build_definition(spec)?;
        let user = VARIANT::from(spec.user_sid());
        let password = VARIANT::default();
        let sddl = VARIANT::from(task_sddl(spec).as_str());
        let flags = TASK_CREATE.0 | TASK_IGNORE_REGISTRATION_TRIGGERS.0;
        // SAFETY: definition contains one validated Exec action, empty
        // triggers, exact current-user principal, and static arguments. CREATE
        // (not UPDATE) ensures a race cannot overwrite a colliding task.
        let registration = unsafe {
            self.root.RegisterTaskDefinition(
                &BSTR::from(spec.task_name()),
                &definition,
                flags,
                &user,
                &password,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &sddl,
            )
        };
        match registration {
            Ok(task) => Self::status_of_registered(spec, &task),
            Err(error) => {
                // A concurrent exact setup may win after our absent check.
                let status = self.status(spec)?;
                match status.state {
                    ScheduledTaskState::Ready | ScheduledTaskState::Running => Ok(status),
                    ScheduledTaskState::Absent => Err(com_error(error, NativeOperation::SetupTask)),
                    other => Err(status_error(other, NativeOperation::SetupTask)),
                }
            }
        }
    }

    /// Request Task Scheduler to start an exact owned task.
    ///
    /// A successful return is not daemon readiness; callers must complete the
    /// authenticated pipe handshake within their guarded startup deadline.
    pub fn request_start(&self, spec: &ScheduledTaskSpec) -> Result<(), NativeError> {
        let task = self
            .get_task(spec)?
            .ok_or_else(|| status_error(ScheduledTaskState::Absent, NativeOperation::StartTask))?;
        let status = Self::status_of_registered(spec, &task)?;
        match status.state {
            ScheduledTaskState::Running => return Ok(()),
            ScheduledTaskState::Ready => {}
            other => return Err(status_error(other, NativeOperation::StartTask)),
        }
        // SAFETY: status verified exact ownership/definition; empty parameters,
        // flags/session/user invoke only the registered static action.
        unsafe {
            task.RunEx(&VARIANT::default(), 0, 0, &BSTR::new())
                .map_err(|error| com_error(error, NativeOperation::StartTask))?;
        }
        Ok(())
    }

    /// Disable only an exact owned task before graceful daemon shutdown.
    pub fn disable_exact(
        &self,
        spec: &ScheduledTaskSpec,
    ) -> Result<ScheduledTaskStatus, NativeError> {
        let task = self.get_task(spec)?.ok_or_else(|| {
            status_error(ScheduledTaskState::Absent, NativeOperation::DisableTask)
        })?;
        let status = Self::status_of_registered(spec, &task)?;
        if !matches!(
            status.state,
            ScheduledTaskState::Ready | ScheduledTaskState::Running | ScheduledTaskState::Disabled
        ) {
            return Err(status_error(status.state, NativeOperation::DisableTask));
        }
        if status.state == ScheduledTaskState::Disabled {
            return Ok(status);
        }
        // SAFETY: status proved exact ownership and definition. This changes
        // only the explicit Enabled lifecycle field.
        unsafe {
            task.SetEnabled(VARIANT_BOOL(0))
                .map_err(|error| com_error(error, NativeOperation::DisableTask))?;
        }
        let disabled = self.status(spec)?;
        if disabled.state != ScheduledTaskState::Disabled {
            return Err(NativeError::new(
                NativeErrorCode::SetupDrifted,
                NativeOperation::DisableTask,
            ));
        }
        Ok(disabled)
    }

    /// Request stop only after an exact owned task has been disabled.
    pub fn stop_exact(&self, spec: &ScheduledTaskSpec) -> Result<ScheduledTaskStatus, NativeError> {
        let task = self
            .get_task(spec)?
            .ok_or_else(|| status_error(ScheduledTaskState::Absent, NativeOperation::StopTask))?;
        let status = Self::status_of_registered(spec, &task)?;
        if status.state != ScheduledTaskState::Disabled {
            return if matches!(
                status.state,
                ScheduledTaskState::Absent
                    | ScheduledTaskState::Drifted
                    | ScheduledTaskState::AccessDenied
                    | ScheduledTaskState::Failed
            ) {
                Err(status_error(status.state, NativeOperation::StopTask))
            } else {
                Err(NativeError::new(
                    NativeErrorCode::TaskNotDisabled,
                    NativeOperation::StopTask,
                ))
            };
        }
        if status.running_instances == 0 {
            return Ok(status);
        }
        // SAFETY: status proved exact ownership, disabled state, and at least
        // one live instance. Stop is a bounded scheduler request, not a wait.
        unsafe {
            task.Stop(0)
                .map_err(|error| com_error(error, NativeOperation::StopTask))?;
        }
        self.status(spec)
    }

    /// Delete only an exact owned, disabled task with no running instances.
    pub fn delete_exact(&self, spec: &ScheduledTaskSpec) -> Result<bool, NativeError> {
        let Some(task) = self.get_task(spec)? else {
            return Ok(false);
        };
        let status = Self::status_of_registered(spec, &task)?;
        if status.state != ScheduledTaskState::Disabled {
            return if matches!(
                status.state,
                ScheduledTaskState::Drifted
                    | ScheduledTaskState::AccessDenied
                    | ScheduledTaskState::Failed
            ) {
                Err(status_error(status.state, NativeOperation::DeleteTask))
            } else {
                Err(NativeError::new(
                    NativeErrorCode::TaskNotDisabled,
                    NativeOperation::DeleteTask,
                ))
            };
        }
        if status.running_instances != 0 {
            return Err(NativeError::new(
                NativeErrorCode::TaskStillRunning,
                NativeOperation::DeleteTask,
            ));
        }
        // SAFETY: the immediately preceding status proves exact ownership,
        // definition, disabled state, and zero scheduler instances.
        unsafe {
            self.root
                .DeleteTask(&BSTR::from(spec.task_name()), 0)
                .map_err(|error| com_error(error, NativeOperation::DeleteTask))?;
        }
        if self.get_task(spec)?.is_some() {
            return Err(NativeError::new(
                NativeErrorCode::SetupDrifted,
                NativeOperation::DeleteTask,
            ));
        }
        Ok(true)
    }

    /// Convenience removal for an already-quiescent task.
    ///
    /// Full uninstall should call [`Self::disable_exact`], attempt authenticated
    /// graceful shutdown and wait for the lifetime lock, then call
    /// [`Self::stop_exact`] only if needed before [`Self::delete_exact`].
    pub fn remove(&self, spec: &ScheduledTaskSpec) -> Result<bool, NativeError> {
        if self.status(spec)?.state == ScheduledTaskState::Absent {
            return Ok(false);
        }
        self.disable_exact(spec)?;
        self.stop_exact(spec)?;
        self.delete_exact(spec)
    }

    fn get_task(&self, spec: &ScheduledTaskSpec) -> Result<Option<IRegisteredTask>, NativeError> {
        // SAFETY: root is live and the generated task name contains only a
        // fixed ASCII prefix plus a base32 scope hash.
        match unsafe { self.root.GetTask(&BSTR::from(spec.task_name())) } {
            Ok(task) => Ok(Some(task)),
            Err(error)
                if matches!(
                    error.code(),
                    HRESULT_FILE_NOT_FOUND | HRESULT_PATH_NOT_FOUND
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(com_error(error, NativeOperation::InspectTask)),
        }
    }

    fn build_definition(spec: &ScheduledTaskSpec) -> Result<ITaskDefinition, NativeError> {
        let service = Self::task_service()?;
        // SAFETY: each setter receives owned BSTR/static enum data and all
        // returned COM interfaces remain live through registration.
        unsafe {
            let definition = service
                .NewTask(0)
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            let registration = definition
                .RegistrationInfo()
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            registration
                .SetURI(&BSTR::from(spec.task_path()))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            registration
                .SetSource(&BSTR::from(spec.owner_uri()))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;

            let principal = definition
                .Principal()
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            principal
                .SetUserId(&BSTR::from(spec.user_sid()))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            principal
                .SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            principal
                .SetRunLevel(TASK_RUNLEVEL_LUA)
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;

            definition
                .Triggers()
                .and_then(|triggers| triggers.Clear())
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            let actions = definition
                .Actions()
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            actions
                .Clear()
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            let action: IExecAction = actions
                .Create(TASK_ACTION_EXEC)
                .and_then(|action| action.cast())
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            action
                .SetPath(&BSTR::from(spec.daemon_path_text.as_str()))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            action
                .SetArguments(&BSTR::from(ARGUMENTS))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            action
                .SetWorkingDirectory(&BSTR::from(spec.working_directory_text.as_str()))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;

            let settings = definition
                .Settings()
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            settings
                .SetAllowDemandStart(VARIANT_BOOL(-1))
                .and_then(|()| settings.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW))
                .and_then(|()| settings.SetExecutionTimeLimit(&BSTR::from(EXECUTION_TIME_LIMIT)))
                .and_then(|()| settings.SetStopIfGoingOnBatteries(VARIANT_BOOL(0)))
                .and_then(|()| settings.SetDisallowStartIfOnBatteries(VARIANT_BOOL(0)))
                .and_then(|()| settings.SetRunOnlyIfIdle(VARIANT_BOOL(0)))
                .and_then(|()| settings.SetRunOnlyIfNetworkAvailable(VARIANT_BOOL(0)))
                .and_then(|()| settings.SetEnabled(VARIANT_BOOL(-1)))
                .and_then(|()| settings.SetRestartCount(0))
                .and_then(|()| settings.SetStartWhenAvailable(VARIANT_BOOL(0)))
                .map_err(|error| com_error(error, NativeOperation::SetupTask))?;
            Ok(definition)
        }
    }

    fn task_service() -> Result<ITaskService, NativeError> {
        // A fresh service avoids retaining a second interface in the public
        // controller while keeping all COM calls on this thread/apartment.
        // SAFETY: the controller's ComApartment is live.
        let service: ITaskService = unsafe {
            CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                .map_err(|error| com_error(error, NativeOperation::ConnectTaskScheduler))?
        };
        let empty = VARIANT::default();
        // SAFETY: empty variants select local/current-user connection.
        unsafe {
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(|error| com_error(error, NativeOperation::ConnectTaskScheduler))?;
        }
        Ok(service)
    }

    fn status_of_registered(
        spec: &ScheduledTaskSpec,
        task: &IRegisteredTask,
    ) -> Result<ScheduledTaskStatus, NativeError> {
        let snapshot = read_snapshot(task, spec)?;
        let actual_digest = snapshot.digest()?;
        let expected = spec.expected_snapshot();
        let last_task_result;
        let running_instances;
        let task_state;
        let task_enabled;
        // SAFETY: task is a live registered-task interface; all queries use
        // local stack outputs or owned returned interfaces.
        unsafe {
            last_task_result = task
                .LastTaskResult()
                .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
            running_instances = task
                .GetInstances(0)
                .and_then(|instances| instances.Count())
                .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
            task_state = task
                .State()
                .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
            task_enabled = task
                .Enabled()
                .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        }
        let binary_matches = sha256_file(spec.daemon_path())? == spec.daemon_sha256;
        // Enabled is an explicit runtime state, not an ownership field. Keep
        // its raw value in `actual_digest`, but normalize only this field for
        // ownership comparison so an exact disabled task remains removable.
        let mut ownership_snapshot = snapshot.clone();
        ownership_snapshot.enabled = true;
        let definition_matches = ownership_snapshot == expected && binary_matches;
        #[cfg(test)]
        if !definition_matches {
            eprintln!("task read-back mismatch\nactual={snapshot:#?}\nexpected={expected:#?}");
        }
        let state = if !definition_matches {
            ScheduledTaskState::Drifted
        } else if task_enabled.0 == 0 {
            ScheduledTaskState::Disabled
        } else if task_state == TASK_STATE_RUNNING || running_instances > 0 {
            ScheduledTaskState::Running
        } else {
            ScheduledTaskState::Ready
        };
        Ok(ScheduledTaskStatus {
            state,
            last_task_result: Some(last_task_result),
            running_instances: u32::try_from(running_instances).unwrap_or(0),
            expected_definition_digest: spec.expected_definition_digest,
            actual_definition_digest: Some(actual_digest),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TaskDefinitionSnapshot {
    registration_uri: String,
    owner_marker: String,
    user_sid: String,
    logon_type: i32,
    run_level: i32,
    trigger_count: i32,
    action_count: i32,
    action_type: i32,
    action_path: String,
    action_arguments: String,
    working_directory: String,
    allow_demand_start: bool,
    multiple_instances: i32,
    execution_time_limit: String,
    stop_if_going_on_batteries: bool,
    disallow_start_if_on_batteries: bool,
    run_only_if_idle: bool,
    run_only_if_network_available: bool,
    enabled: bool,
    restart_count: i32,
    start_when_available: bool,
    security_exact: bool,
}

impl TaskDefinitionSnapshot {
    fn digest(&self) -> Result<[u8; 32], NativeError> {
        let mut hasher = Sha256::new();
        digest_field(&mut hasher, b"codex-agent-mesh\0task-definition-v1\0")?;
        for value in [
            self.registration_uri.as_str(),
            self.owner_marker.as_str(),
            self.user_sid.as_str(),
            &self.logon_type.to_string(),
            &self.run_level.to_string(),
            &self.trigger_count.to_string(),
            &self.action_count.to_string(),
            &self.action_type.to_string(),
            self.action_path.as_str(),
            self.action_arguments.as_str(),
            self.working_directory.as_str(),
            bool_text(self.allow_demand_start),
            &self.multiple_instances.to_string(),
            self.execution_time_limit.as_str(),
            bool_text(self.stop_if_going_on_batteries),
            bool_text(self.disallow_start_if_on_batteries),
            bool_text(self.run_only_if_idle),
            bool_text(self.run_only_if_network_available),
            bool_text(self.enabled),
            &self.restart_count.to_string(),
            bool_text(self.start_when_available),
            bool_text(self.security_exact),
        ] {
            digest_field(&mut hasher, value.as_bytes())?;
        }
        Ok(hasher.finalize().into())
    }
}

fn read_snapshot(
    task: &IRegisteredTask,
    spec: &ScheduledTaskSpec,
) -> Result<TaskDefinitionSnapshot, NativeError> {
    // SAFETY: all COM interfaces are live and every getter writes into a
    // correctly typed stack output or owned BSTR.
    unsafe {
        let definition = task
            .Definition()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let registration = definition
            .RegistrationInfo()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut registration_uri = BSTR::new();
        let mut owner_marker = BSTR::new();
        registration
            .URI(&raw mut registration_uri)
            .and_then(|()| registration.Source(&raw mut owner_marker))
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;

        let principal = definition
            .Principal()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut user_sid = BSTR::new();
        let mut logon_type = TASK_LOGON_INTERACTIVE_TOKEN;
        let mut run_level = TASK_RUNLEVEL_LUA;
        principal
            .UserId(&raw mut user_sid)
            .and_then(|()| principal.LogonType(&raw mut logon_type))
            .and_then(|()| principal.RunLevel(&raw mut run_level))
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;

        let triggers = definition
            .Triggers()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut trigger_count = 0;
        triggers
            .Count(&raw mut trigger_count)
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;

        let actions = definition
            .Actions()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut action_count = 0;
        actions
            .Count(&raw mut action_count)
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        if action_count != 1 {
            return Ok(invalid_snapshot(
                registration_uri,
                owner_marker,
                user_sid,
                logon_type.0,
                run_level.0,
                trigger_count,
                action_count,
            ));
        }
        let action: IAction = actions
            .get_Item(1)
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut action_type = TASK_ACTION_EXEC;
        action
            .Type(&raw mut action_type)
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let action: IExecAction = action
            .cast()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut action_path = BSTR::new();
        let mut action_arguments = BSTR::new();
        let mut working_directory = BSTR::new();
        action
            .Path(&raw mut action_path)
            .and_then(|()| action.Arguments(&raw mut action_arguments))
            .and_then(|()| action.WorkingDirectory(&raw mut working_directory))
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;

        let settings = definition
            .Settings()
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;
        let mut allow_demand_start = VARIANT_BOOL(0);
        let mut multiple_instances = TASK_INSTANCES_IGNORE_NEW;
        let mut execution_time_limit = BSTR::new();
        let mut stop_if_going_on_batteries = VARIANT_BOOL(0);
        let mut disallow_start_if_on_batteries = VARIANT_BOOL(0);
        let mut run_only_if_idle = VARIANT_BOOL(0);
        let mut run_only_if_network_available = VARIANT_BOOL(0);
        let mut enabled = VARIANT_BOOL(0);
        let mut restart_count = 0;
        let mut start_when_available = VARIANT_BOOL(0);
        settings
            .AllowDemandStart(&raw mut allow_demand_start)
            .and_then(|()| settings.MultipleInstances(&raw mut multiple_instances))
            .and_then(|()| settings.ExecutionTimeLimit(&raw mut execution_time_limit))
            .and_then(|()| settings.StopIfGoingOnBatteries(&raw mut stop_if_going_on_batteries))
            .and_then(|()| {
                settings.DisallowStartIfOnBatteries(&raw mut disallow_start_if_on_batteries)
            })
            .and_then(|()| settings.RunOnlyIfIdle(&raw mut run_only_if_idle))
            .and_then(|()| {
                settings.RunOnlyIfNetworkAvailable(&raw mut run_only_if_network_available)
            })
            .and_then(|()| settings.Enabled(&raw mut enabled))
            .and_then(|()| settings.RestartCount(&raw mut restart_count))
            .and_then(|()| settings.StartWhenAvailable(&raw mut start_when_available))
            .map_err(|error| com_error(error, NativeOperation::InspectTask))?;

        Ok(TaskDefinitionSnapshot {
            registration_uri: registration_uri.to_string(),
            owner_marker: owner_marker.to_string(),
            user_sid: principal_sid_string(&user_sid.to_string())?,
            logon_type: logon_type.0,
            run_level: run_level.0,
            trigger_count,
            action_count,
            action_type: action_type.0,
            action_path: action_path.to_string(),
            action_arguments: action_arguments.to_string(),
            working_directory: working_directory.to_string(),
            allow_demand_start: allow_demand_start.0 != 0,
            multiple_instances: multiple_instances.0,
            execution_time_limit: execution_time_limit.to_string(),
            stop_if_going_on_batteries: stop_if_going_on_batteries.0 != 0,
            disallow_start_if_on_batteries: disallow_start_if_on_batteries.0 != 0,
            run_only_if_idle: run_only_if_idle.0 != 0,
            run_only_if_network_available: run_only_if_network_available.0 != 0,
            enabled: enabled.0 != 0,
            restart_count,
            start_when_available: start_when_available.0 != 0,
            security_exact: verify_task_dacl(task, spec)?,
        })
    }
}

fn invalid_snapshot(
    registration_uri: BSTR,
    owner_marker: BSTR,
    user_sid: BSTR,
    logon_type: i32,
    run_level: i32,
    trigger_count: i32,
    action_count: i32,
) -> TaskDefinitionSnapshot {
    TaskDefinitionSnapshot {
        registration_uri: registration_uri.to_string(),
        owner_marker: owner_marker.to_string(),
        user_sid: user_sid.to_string(),
        logon_type,
        run_level,
        trigger_count,
        action_count,
        action_type: -1,
        action_path: String::new(),
        action_arguments: String::new(),
        working_directory: String::new(),
        allow_demand_start: false,
        multiple_instances: -1,
        execution_time_limit: String::new(),
        stop_if_going_on_batteries: true,
        disallow_start_if_on_batteries: true,
        run_only_if_idle: true,
        run_only_if_network_available: true,
        enabled: false,
        restart_count: -1,
        start_when_available: true,
        security_exact: false,
    }
}

fn digest_field(hasher: &mut Sha256, value: &[u8]) -> Result<(), NativeError> {
    let length = u32::try_from(value.len()).map_err(|_| invalid_task_spec())?;
    hasher.update(length.to_le_bytes());
    hasher.update(value);
    Ok(())
}

const fn bool_text(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn task_sddl(spec: &ScheduledTaskSpec) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{})", spec.user_sid())
}

fn verify_task_dacl(task: &IRegisteredTask, spec: &ScheduledTaskSpec) -> Result<bool, NativeError> {
    // SAFETY: task is live and the returned BSTR is independently owned.
    let sddl = unsafe {
        task.GetSecurityDescriptor(
            i32::try_from(DACL_SECURITY_INFORMATION).expect("DACL information flag fits i32"),
        )
        .map_err(|error| com_error(error, NativeOperation::InspectTask))?
    };
    let sddl = std::ffi::OsStr::new(&sddl.to_string())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    // SAFETY: SDDL is NUL-terminated and output receives LocalAlloc storage.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(last_task_native_error());
    }
    let descriptor = OwnedLocalDescriptor(descriptor);
    let user_sid = owned_string_sid(spec.user_sid())?;
    let system_sid = well_known_sid(WinLocalSystemSid).map_err(|error| {
        error.os_code().map_or_else(
            || NativeError::new(NativeErrorCode::OsFailure, NativeOperation::InspectTask),
            |code| {
                NativeError::with_os_code(
                    NativeErrorCode::OsFailure,
                    NativeOperation::InspectTask,
                    code,
                )
            },
        )
    })?;
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: descriptor and outputs are live. A null/unrestricted DACL fails closed.
    let got_dacl = unsafe {
        GetSecurityDescriptorDacl(
            descriptor.0,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    };
    if got_dacl == 0 || present == 0 || dacl.is_null() {
        return Ok(false);
    }
    // SAFETY: the successful descriptor query returned a non-null,
    // descriptor-owned ACL pointer which remains live with `descriptor`.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Ok(false);
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and information is the exact class structure.
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast::<c_void>(),
            u32::try_from(mem::size_of::<ACL_SIZE_INFORMATION>())
                .expect("ACL information size fits u32"),
            AclSizeInformation,
        )
    } == 0
        || information.AceCount < 2
    {
        return Ok(false);
    }
    let mut user_mask = 0_u32;
    let mut system_mask = 0_u32;
    for index in 0..information.AceCount {
        let mut ace = ptr::null_mut();
        // SAFETY: index is bounded by the queried ACE count.
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
            return Ok(false);
        }
        // SAFETY: GetAce returns an ACE beginning with ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType != u8::try_from(ACCESS_ALLOWED_ACE_TYPE).expect("ACE type fits u8")
            || header.AceFlags != 0
            || usize::from(header.AceSize) < mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Ok(false);
        }
        // SAFETY: accepted access-allowed ACE has the fixed leading layout.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid: PSID = (&raw const allowed.SidStart).cast_mut().cast();
        if unsafe { IsValidSid(sid) } == 0 {
            return Ok(false);
        }
        if !access_allowed_ace_size_is_exact(header.AceSize, sid) {
            return Ok(false);
        }
        if same_sid(sid, user_sid.0) {
            user_mask |= allowed.Mask;
        } else if same_sid(sid, system_sid.as_ptr().cast_mut().cast()) {
            system_mask |= allowed.Mask;
        } else {
            return Ok(false);
        }
    }
    // Task Scheduler may split a principal's full/read rights into redundant
    // allow ACEs. Canonicalize by principal-mask union, never by ignoring ACEs.
    Ok(user_mask == FILE_ALL_ACCESS && system_mask == FILE_ALL_ACCESS)
}

fn owned_string_sid(value: &str) -> Result<OwnedLocalSid, NativeError> {
    let wide = std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid = ptr::null_mut();
    // SAFETY: input is NUL-terminated and output receives LocalAlloc storage.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &raw mut sid) } == 0 || sid.is_null() {
        return Err(last_task_native_error());
    }
    Ok(OwnedLocalSid(sid))
}

struct OwnedLocalDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedLocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: SDDL conversion allocated this descriptor with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

struct OwnedLocalSid(PSID);

impl Drop for OwnedLocalSid {
    fn drop(&mut self) {
        // SAFETY: string SID conversion allocated this SID with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

fn principal_sid_string(account_name: &str) -> Result<String, NativeError> {
    if account_name.is_empty() || account_name.as_bytes().contains(&0) {
        return Err(invalid_task_spec());
    }
    let account = std::ffi::OsStr::new(account_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid_size = 0_u32;
    let mut domain_size = 0_u32;
    let mut sid_use = SID_NAME_USE::default();
    // SAFETY: null-buffer query obtains exact SID/domain capacities.
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &raw mut sid_size,
            ptr::null_mut(),
            &raw mut domain_size,
            &raw mut sid_use,
        )
    };
    // SAFETY: called immediately after the expected sizing failure.
    if sid_size == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_task_native_error());
    }
    let sid_words = usize::try_from(sid_size)
        .ok()
        .and_then(|bytes| bytes.checked_add(mem::size_of::<usize>() - 1))
        .and_then(|bytes| bytes.checked_div(mem::size_of::<usize>()))
        .ok_or_else(invalid_task_spec)?;
    let mut sid = vec![0_usize; sid_words];
    let mut domain = vec![0_u16; usize::try_from(domain_size).map_err(|_| invalid_task_spec())?];
    // SAFETY: both aligned buffers have the exact queried capacities and all
    // size/use values are live mutable outputs.
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_size,
            domain.as_mut_ptr(),
            &raw mut domain_size,
            &raw mut sid_use,
        )
    } == 0
    {
        return Err(last_task_native_error());
    }
    let sid_ptr = sid.as_mut_ptr().cast();
    // SAFETY: LookupAccountNameW returned a SID in the aligned buffer.
    if unsafe { IsValidSid(sid_ptr) } == 0 {
        return Err(invalid_task_spec());
    }
    let mut output = ptr::null_mut();
    // SAFETY: valid SID input; output receives LocalAlloc UTF-16 storage.
    if unsafe { ConvertSidToStringSidW(sid_ptr, &raw mut output) } == 0 || output.is_null() {
        return Err(last_task_native_error());
    }
    let local = OwnedSidString(output);
    let mut length = 0_usize;
    // SAFETY: the conversion returns a NUL-terminated string allocation.
    while unsafe { *local.0.add(length) } != 0 {
        length = length.checked_add(1).ok_or_else(invalid_task_spec)?;
    }
    // SAFETY: length was found inside the allocation.
    String::from_utf16(unsafe { slice::from_raw_parts(local.0, length) })
        .map_err(|_| invalid_task_spec())
}

struct OwnedSidString(*mut u16);

impl Drop for OwnedSidString {
    fn drop(&mut self) {
        // SAFETY: ConvertSidToStringSidW allocated with LocalAlloc.
        unsafe { LocalFree(self.0.cast()) };
    }
}

fn last_task_native_error() -> NativeError {
    // SAFETY: called immediately after a failing Win32 operation.
    let code = unsafe { GetLastError() };
    NativeError::with_os_code(
        NativeErrorCode::OsFailure,
        NativeOperation::InspectTask,
        code,
    )
}

fn status_error(state: ScheduledTaskState, operation: NativeOperation) -> NativeError {
    let code = match state {
        ScheduledTaskState::Absent => NativeErrorCode::SetupAbsent,
        ScheduledTaskState::Disabled => NativeErrorCode::SetupDisabled,
        ScheduledTaskState::Drifted => NativeErrorCode::SetupDrifted,
        ScheduledTaskState::AccessDenied => NativeErrorCode::SetupAccessDenied,
        ScheduledTaskState::Failed | ScheduledTaskState::Ready | ScheduledTaskState::Running => {
            NativeErrorCode::OsFailure
        }
    };
    NativeError::new(code, operation)
}

#[derive(Debug)]
struct ComApartment {
    uninitialize: bool,
    // COM initialization is thread-affine. This marker makes both this guard
    // and every controller that owns it !Send + !Sync, ensuring interfaces
    // are released and CoUninitialize runs on the initializing thread.
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl ComApartment {
    fn initialize() -> Result<Self, NativeError> {
        // SAFETY: null reserved pointer and MTA are valid. The guard balances
        // successful initialization on the same thread.
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_ok() {
            Ok(Self {
                uninitialize: true,
                _not_send_or_sync: PhantomData,
            })
        } else if result == RPC_E_CHANGED_MODE {
            Ok(Self {
                uninitialize: false,
                _not_send_or_sync: PhantomData,
            })
        } else {
            Err(hresult_error(result, NativeOperation::ConnectTaskScheduler))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            // SAFETY: this thread successfully initialized COM in `initialize`.
            unsafe { CoUninitialize() };
        }
    }
}

fn com_error(error: windows::core::Error, operation: NativeOperation) -> NativeError {
    hresult_error(error.code(), operation)
}

fn hresult_error(code: HRESULT, operation: NativeOperation) -> NativeError {
    NativeError::with_os_code(
        if code == E_ACCESSDENIED {
            NativeErrorCode::SetupAccessDenied
        } else {
            NativeErrorCode::OsFailure
        },
        operation,
        code.0.cast_unsigned(),
    )
}

fn io_error(error: &std::io::Error, operation: NativeOperation) -> NativeError {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .map_or_else(
            || NativeError::new(NativeErrorCode::OsFailure, operation),
            |code| NativeError::with_os_code(NativeErrorCode::OsFailure, operation, code),
        )
}

const fn invalid_task_spec() -> NativeError {
    NativeError::new(
        NativeErrorCode::InvalidArgument,
        NativeOperation::InspectTask,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_definition_digest_changes_for_security_relevant_fields() {
        let mut snapshot = TaskDefinitionSnapshot {
            registration_uri: r"\CodexAgentMesh-test-owner".to_owned(),
            owner_marker: "owner".to_owned(),
            user_sid: "S-1-5-21-1".to_owned(),
            logon_type: TASK_LOGON_INTERACTIVE_TOKEN.0,
            run_level: TASK_RUNLEVEL_LUA.0,
            trigger_count: 0,
            action_count: 1,
            action_type: TASK_ACTION_EXEC.0,
            action_path: r"C:\Program Files\网格\mesh-daemon.exe".to_owned(),
            action_arguments: ARGUMENTS.to_owned(),
            working_directory: r"C:\Program Files\网格".to_owned(),
            allow_demand_start: true,
            multiple_instances: TASK_INSTANCES_IGNORE_NEW.0,
            execution_time_limit: EXECUTION_TIME_LIMIT.to_owned(),
            stop_if_going_on_batteries: false,
            disallow_start_if_on_batteries: false,
            run_only_if_idle: false,
            run_only_if_network_available: false,
            enabled: true,
            restart_count: 0,
            start_when_available: false,
            security_exact: true,
        };
        let original = snapshot.digest().expect("digest");
        snapshot.trigger_count = 1;
        assert_ne!(snapshot.digest().expect("changed"), original);
        snapshot.trigger_count = 0;
        snapshot.action_arguments.push_str(" --unexpected");
        assert_ne!(snapshot.digest().expect("changed args"), original);
    }

    #[test]
    fn task_setup_status_and_remove_live_fixture() {
        if std::env::var_os("MESH_WIN32_TASK_TEST").is_none() {
            eprintln!("skipped: set MESH_WIN32_TASK_TEST=1 in an interactive user session");
            return;
        }
        let executable = std::env::current_exe().expect("current exe");
        let digest = sha256_file(&executable).expect("digest");
        let mut install_bytes = [0_u8; 16];
        getrandom::fill(&mut install_bytes).expect("random install id");
        let install_id = data_encoding::HEXLOWER.encode(&install_bytes);
        let mut spec = ScheduledTaskSpec::new(&install_id, executable, digest).expect("spec");
        let scope = spec
            .task_name
            .strip_prefix(TASK_PREFIX)
            .expect("scope")
            .to_owned();
        spec.task_name = format!("CodexAgentMesh-test-{scope}");
        spec.owner_uri = format!("urn:codex-agent-mesh:test:{install_id}");
        spec.expected_definition_digest = spec.expected_snapshot().digest().expect("test digest");
        let controller = ScheduledTaskController::connect().expect("task scheduler");
        let mut cleanup = TestTaskCleanup {
            controller: &controller,
            spec: &spec,
            armed: true,
        };
        assert_eq!(
            controller.status(&spec).expect("absent").state,
            ScheduledTaskState::Absent
        );
        let setup = controller.setup(&spec).expect("setup");
        assert_eq!(setup.state, ScheduledTaskState::Ready);
        assert_eq!(
            setup.actual_definition_digest,
            Some(*spec.expected_definition_digest())
        );
        assert_eq!(
            controller
                .delete_exact(&spec)
                .expect_err("delete requires disable")
                .code(),
            NativeErrorCode::TaskNotDisabled
        );
        let disabled = controller.disable_exact(&spec).expect("disable exact task");
        let stopped = controller.stop_exact(&spec).expect("stop exact task");
        let ordinary_remove =
            if stopped.state == ScheduledTaskState::Disabled && stopped.running_instances == 0 {
                controller.delete_exact(&spec).expect("delete exact task")
            } else {
                cleanup_test_task(&controller, &spec);
                false
            };
        assert_eq!(disabled.state, ScheduledTaskState::Disabled);
        assert_ne!(
            disabled.actual_definition_digest,
            Some(*spec.expected_definition_digest())
        );
        assert_eq!(stopped.state, ScheduledTaskState::Disabled);
        assert!(ordinary_remove);
        assert_eq!(
            controller.status(&spec).expect("removed").state,
            ScheduledTaskState::Absent
        );
        cleanup.armed = false;
    }

    struct TestTaskCleanup<'a> {
        controller: &'a ScheduledTaskController,
        spec: &'a ScheduledTaskSpec,
        armed: bool,
    }

    impl Drop for TestTaskCleanup<'_> {
        fn drop(&mut self) {
            if self.armed {
                cleanup_test_task(self.controller, self.spec);
            }
        }
    }

    fn cleanup_test_task(controller: &ScheduledTaskController, spec: &ScheduledTaskSpec) {
        if !spec.task_name().starts_with("CodexAgentMesh-test-") {
            return;
        }
        let Ok(Some(task)) = controller.get_task(spec) else {
            return;
        };
        let Ok(snapshot) = read_snapshot(&task, spec) else {
            return;
        };
        if snapshot.registration_uri != spec.task_path()
            || snapshot.owner_marker != spec.owner_uri()
        {
            return;
        }
        // SAFETY: the test-only name and independent Source marker both match
        // this randomized fixture; no production/colliding task is touched.
        unsafe {
            let _ = task.SetEnabled(VARIANT_BOOL(0));
            let _ = task.Stop(0);
            let _ = controller.root.DeleteTask(&BSTR::from(spec.task_name()), 0);
        }
    }
}
