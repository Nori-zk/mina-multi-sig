use std::io::{BufRead, BufReader};
use std::mem;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;

fn block_signals() {
    unsafe {
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
}

fn wait_set() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        set
    }
}

// Children inherit the blocked signal mask. Reset it in their process image
// before exec so they receive signals normally.
fn unblock_signals_pre_exec() {
    unsafe {
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigprocmask(libc::SIG_SETMASK, &set, std::ptr::null_mut());
    }
}

fn spawn_frostd() -> Child {
    eprintln!("[supervisor] starting frostd on 127.0.0.1:12744");
    unsafe {
        Command::new("/usr/local/bin/frostd")
            .args(["--no-tls-very-insecure", "--port", "12744"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(|| {
                unblock_signals_pre_exec();
                Ok(())
            })
            .spawn()
            .expect("[supervisor] failed to spawn frostd")
    }
}

fn spawn_nginx() -> Child {
    eprintln!("[supervisor] starting nginx on 0.0.0.0:2744 -> 127.0.0.1:12744");
    unsafe {
        Command::new("/usr/sbin/nginx")
            .args(["-e", "/dev/stderr", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .pre_exec(|| {
                unblock_signals_pre_exec();
                Ok(())
            })
            .spawn()
            .expect("[supervisor] failed to spawn nginx")
    }
}

fn pipe_output(stdout: std::process::ChildStdout, stderr: std::process::ChildStderr, prefix: &'static str) {
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => eprintln!("[{}] {}", prefix, l),
                Err(_) => break,
            }
        }
    });
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(l) => eprintln!("[{}] {}", prefix, l),
                Err(_) => break,
            }
        }
    });
}

// Reap zombies, returning any PIDs that exited.
fn reap_zombies() -> Vec<libc::pid_t> {
    let mut exited = Vec::new();
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break;
        }
        exited.push(pid);
    }
    exited
}

fn send_sigterm(child: &Child, name: &str) {
    eprintln!("[supervisor] sending SIGTERM to {}", name);
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
}

fn wait_or_kill(child: &mut Child, name: &str) {
    // waitpid in a brief spin — we already got SIGCHLD so it should be gone.
    for _ in 0..50 {
        match child.try_wait() {
            Ok(Some(s)) => { eprintln!("[supervisor] {} exited: {}", name, s); return; }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => { eprintln!("[supervisor] error waiting for {}: {}", name, e); return; }
        }
    }
    eprintln!("[supervisor] {} did not stop in time, sending SIGKILL", name);
    let _ = child.kill();
    let _ = child.wait();
}

fn main() {
    // Block signals before spawning so no signal is missed between spawn and sigwaitinfo.
    block_signals();

    eprintln!("[supervisor] starting");

    let mut frostd = spawn_frostd();
    let mut nginx = spawn_nginx();

    let frostd_pid = frostd.id() as libc::pid_t;
    let nginx_pid = nginx.id() as libc::pid_t;

    pipe_output(
        frostd.stdout.take().unwrap(),
        frostd.stderr.take().unwrap(),
        "frostd",
    );
    pipe_output(
        nginx.stdout.take().unwrap(),
        nginx.stderr.take().unwrap(),
        "nginx",
    );

    let set = wait_set();

    // Event loop — blocks in sigwaitinfo until a signal arrives.
    loop {
        let mut info: libc::siginfo_t = unsafe { mem::zeroed() };
        let sig = unsafe { libc::sigwaitinfo(&set, &mut info) };

        match sig {
            libc::SIGCHLD => {
                for pid in reap_zombies() {
                    if pid == frostd_pid {
                        eprintln!("[supervisor] frostd exited unexpectedly, shutting down");
                    } else if pid == nginx_pid {
                        eprintln!("[supervisor] nginx exited unexpectedly, shutting down");
                    }
                }
                // Either child exiting is fatal — fall through to shutdown.
                break;
            }
            libc::SIGTERM | libc::SIGINT => {
                eprintln!("[supervisor] received signal {}, shutting down", sig);
                break;
            }
            _ => {}
        }
    }

    send_sigterm(&nginx, "nginx");
    send_sigterm(&frostd, "frostd");
    wait_or_kill(&mut nginx, "nginx");
    wait_or_kill(&mut frostd, "frostd");

    eprintln!("[supervisor] all processes stopped, exiting");
}
