use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use tauri::Manager;

struct BackendProcess(Mutex<Option<Child>>);

fn find_python() -> Option<String> {
    let candidates = if cfg!(target_os = "windows") {
        vec!["python", "python3", "py"]
    } else {
        vec!["python3", "python"]
    };
    for c in candidates {
        if which::which(c).is_ok() {
            return Some(c.to_string());
        }
    }
    None
}

fn spawn_backend(app: &tauri::App) -> std::io::Result<Child> {
    let log_dir = std::env::var("LOCALAPPDATA")
        .or_else(|_| std::env::var("APPDATA"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("fstec-service");
    std::fs::create_dir_all(&log_dir).ok();
    let log_file = log_dir.join("backend.log");
    let log_handle = OpenOptions::new().create(true).append(true).open(&log_file)?;
    let err_handle = log_handle.try_clone()?;

    if cfg!(debug_assertions) {
        let python = match find_python() {
            Some(p) => p,
            None => {
                log::error!("Python not found in PATH");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "python not found",
                ));
            }
        };
        let backend_dir = std::env::current_dir()
            .map(|d| d.parent().unwrap().join("backend"))
            .expect("failed to resolve backend dir");
        return Command::new(&python)
            .arg("-m")
            .arg("uvicorn")
            .arg("app.main:app")
            .arg("--host")
            .arg("127.0.0.1")
            .arg("--port")
            .arg("8765")
            .current_dir(&backend_dir)
            .stdout(Stdio::from(log_handle))
            .stderr(Stdio::from(err_handle))
            .spawn();
    }

    let resource_dir = app
        .path()
        .resource_dir()
        .expect("failed to resolve resource dir");
    let candidates = [
        resource_dir.join("fstec-backend").join(if cfg!(target_os = "windows") { "fstec-backend.exe" } else { "fstec-backend" }),
        resource_dir
            .join("backend")
            .join("dist")
            .join("fstec-backend")
            .join(if cfg!(target_os = "windows") { "fstec-backend.exe" } else { "fstec-backend" }),
    ];
    let exe_path = candidates
        .into_iter()
        .find(|p| p.exists())
        .expect("failed to locate backend executable in resources");
    log::info!("Starting backend: {}", exe_path.display());
    Command::new(&exe_path)
        .stdout(Stdio::from(log_handle))
        .stderr(Stdio::from(err_handle))
        .spawn()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(BackendProcess(Mutex::new(None)))
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let child = spawn_backend(app);

            match child {
                Ok(c) => {
                    log::info!("Backend started (PID: {})", c.id());
                    let state: tauri::State<BackendProcess> = app.state();
                    let mut guard = state.0.lock().unwrap();
                    *guard = Some(c);
                }
                Err(e) => {
                    log::error!("Failed to start backend: {}", e);
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                let state: tauri::State<BackendProcess> = window.state();
                let mut guard = state.0.lock().unwrap();
                if let Some(mut child) = guard.take() {
                    let _ = child.kill();
                    log::info!("Backend stopped");
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
