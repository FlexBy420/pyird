import tkinter as tk

def make_tooltip(widget, text_fn, *, offset_x=4, offset_y=2, font=("", 10)):
    tip: list = [None]
    after_id: list = [None]

    def _destroy():
        if after_id[0]:
            try:
                widget.after_cancel(after_id[0])
            except Exception:
                pass
            after_id[0] = None
        if tip[0]:
            try:
                tip[0].destroy()
            except Exception:
                pass
            tip[0] = None

    def _show():
        after_id[0] = None
        msg = text_fn()
        if not msg or tip[0]:
            return
        try:
            tw = tk.Toplevel(widget)
            tw.overrideredirect(True)
            tw.withdraw()
            tw.attributes("-topmost", True)
            tw.attributes("-alpha", 0.95)
            tk.Label(
                tw, text=msg, font=font,
                background="#2b2b2b", foreground="white",
                relief="flat", padx=6, pady=3,
                justify="left",
            ).pack()
            tw.update_idletasks()
            x = widget.winfo_rootx() + offset_x
            y = widget.winfo_rooty() + widget.winfo_height() + offset_y
            tw.wm_geometry(f"+{x}+{y}")
            tw.deiconify()
            tip[0] = tw
        except Exception:
            pass

    def _enter(_e):
        if after_id[0]:
            return
        after_id[0] = widget.after(400, _show)

    def _leave(_e):
        _destroy()

    widget.bind("<Enter>", _enter, add="+")
    widget.bind("<Leave>", _leave, add="+")
    widget.bind("<Destroy>", lambda _e: _destroy(), add="+")
    return _destroy

def bind_tooltip(widget, text_fn, **kwargs):
    return make_tooltip(widget, text_fn, **kwargs)
