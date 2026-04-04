"""
Settings dialog for SecureTunnel.

Opens a modal tkinter window where the user can configure ports and VPS hosts.

Usage:
    from secure_tunnel.ui.settings_dialog import open_settings_dialog
    open_settings_dialog(root, is_running=self._running, base=BASE,
                         settings=_load_settings(BASE),
                         save_fn=lambda s: _save_settings(BASE, s),
                         log_fn=self.log_line)
"""
import tkinter as tk


def open_settings_dialog(
    root: tk.Tk,
    is_running: bool,
    settings: dict,
    save_fn,
    log_fn,
) -> None:
    """
    Open the settings modal dialog.

    Parameters
    ----------
    root       : parent tkinter window
    is_running : whether the tunnel is currently running (disables save)
    settings   : current settings dict (from _load_settings)
    save_fn    : callable(new_settings_dict) — persists settings
    log_fn     : callable(text, tag) — writes to the launcher log
    """
    if is_running:
        log_fn("[launcher] Останови туннель перед изменением настроек.\n", "err")
        return

    dlg = tk.Toplevel(root)
    dlg.title("Настройки SecureTunnel")
    dlg.resizable(False, False)
    dlg.grab_set()
    dlg.configure(bg="#252526")

    # ── Режим: Локальный / Удалённый ─────────────────────────────────────────
    mode_var = tk.StringVar(value=settings.get("mode", "local"))
    mode_frame = tk.Frame(dlg, bg="#252526")
    mode_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(8, 2), sticky="w")
    tk.Label(mode_frame, text="Режим:", bg="#252526", fg="#9cdcfe",
             font=("Consolas", 9, "bold")).pack(side="left")
    tk.Radiobutton(mode_frame, text="Локальный (все узлы здесь)", variable=mode_var,
                   value="local", bg="#252526", fg="#d4d4d4", selectcolor="#3c3c3c",
                   font=("Consolas", 9), activebackground="#252526",
                   activeforeground="white").pack(side="left", padx=8)
    tk.Radiobutton(mode_frame, text="Удалённый (VPS серверы)", variable=mode_var,
                   value="remote", bg="#252526", fg="#d4d4d4", selectcolor="#3c3c3c",
                   font=("Consolas", 9), activebackground="#252526",
                   activeforeground="white").pack(side="left", padx=4)

    # ── Порты ────────────────────────────────────────────────────────────────
    tk.Label(dlg, text="── Локальные порты ──", bg="#252526", fg="#569cd6",
             font=("Consolas", 9)).grid(row=1, column=0, columnspan=2, pady=(6, 2))

    port_fields = [
        ("SOCKS5 порт",  "socks5_port",  str(settings.get("socks5_port", 1080))),
        ("HTTP порт",    "http_port",    str(settings.get("http_port",   8080))),
        ("Entry порт",   "entry_port",   str(settings.get("entry_port",  8765))),
        ("Middle порт",  "middle_port",  str(settings.get("middle_port", 8766))),
        ("Exit порт",    "exit_port",    str(settings.get("exit_port",   8767))),
    ]

    entries: dict[str, tk.StringVar] = {}
    for i, (label, key, default) in enumerate(port_fields):
        row = i + 2
        tk.Label(dlg, text=label, bg="#252526", fg="#d4d4d4",
                 font=("Consolas", 9), anchor="w", width=16).grid(
            row=row, column=0, padx=10, pady=3, sticky="w")
        var = tk.StringVar(value=default)
        tk.Entry(dlg, textvariable=var, width=8, bg="#3c3c3c", fg="white",
                 insertbackground="white", relief="flat",
                 font=("Consolas", 9)).grid(row=row, column=1, padx=10, pady=3, sticky="w")
        entries[key] = var

    # ── VPS адреса (Remote режим) ─────────────────────────────────────────────
    tk.Label(dlg, text="── VPS адреса (Remote режим) ──", bg="#252526", fg="#569cd6",
             font=("Consolas", 9)).grid(row=7, column=0, columnspan=2, pady=(8, 2))

    vps_fields = [
        ("Entry IP",   "entry_host",   settings.get("entry_host",  "127.0.0.1")),
        ("Middle IP",  "middle_host",  settings.get("middle_host", "127.0.0.1")),
        ("Exit IP",    "exit_host",    settings.get("exit_host",   "127.0.0.1")),
    ]
    for i, (label, key, default) in enumerate(vps_fields):
        row = i + 8
        tk.Label(dlg, text=label, bg="#252526", fg="#d4d4d4",
                 font=("Consolas", 9), anchor="w", width=16).grid(
            row=row, column=0, padx=10, pady=3, sticky="w")
        var = tk.StringVar(value=default)
        tk.Entry(dlg, textvariable=var, width=18, bg="#3c3c3c", fg="white",
                 insertbackground="white", relief="flat",
                 font=("Consolas", 9)).grid(row=row, column=1, padx=10, pady=3, sticky="w")
        entries[key] = var

    # ── Кнопки ───────────────────────────────────────────────────────────────
    port_keys = {f[1] for f in port_fields}

    def save():
        new: dict = {"mode": mode_var.get()}
        for key, var in entries.items():
            if key in port_keys:
                try:
                    val = int(var.get())
                    if not (1 <= val <= 65535):
                        raise ValueError
                    new[key] = val
                except ValueError:
                    log_fn(f"[launcher] Неверный порт для {key}.\n", "err")
                    return
            else:
                new[key] = var.get().strip()
        save_fn(new)
        log_fn("[launcher] Настройки сохранены. Применятся при следующем запуске.\n", "info")
        dlg.destroy()

    def reset():
        mode_var.set("local")
        defaults = {
            "socks5_port": 1080, "http_port": 8080,
            "entry_port": 8765, "middle_port": 8766, "exit_port": 8767,
            "entry_host": "127.0.0.1", "middle_host": "127.0.0.1",
            "exit_host": "127.0.0.1",
        }
        for key, var in entries.items():
            var.set(str(defaults.get(key, "")))

    total_rows = len(port_fields) + len(vps_fields) + 3
    btn_frame = tk.Frame(dlg, bg="#252526")
    btn_frame.grid(row=total_rows, column=0, columnspan=2, pady=8)
    tk.Button(btn_frame, text="Сохранить", command=save,
              bg="#0e639c", fg="white", relief="flat", width=12).pack(side="left", padx=6)
    tk.Button(btn_frame, text="По умолчанию", command=reset,
              bg="#3a3a3a", fg="white", relief="flat", width=14).pack(side="left", padx=6)
    tk.Button(btn_frame, text="Отмена", command=dlg.destroy,
              bg="#3a3a3a", fg="white", relief="flat", width=10).pack(side="left", padx=6)
