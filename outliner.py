"""
Author: Milankovo, 2026
License: MIT
"""

import idaapi


class outline_func_action_handler_t(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx: idaapi.action_ctx_base_t):
        func: idaapi.func_t = ctx.cur_func
        if not func:
            return 0
        
        # without this, ida complains the the action is not undo-friendly
        func = idaapi.get_func(func.start_ea)
        if not func:
            return 0

        func.flags |= idaapi.FUNC_OUTLINE
        idaapi.update_func(func)
        return 1

    def update(self, ctx: idaapi.action_ctx_base_t):
        return (
            idaapi.AST_ENABLE_FOR_WIDGET
            if ctx.widget_type == idaapi.BWN_PSEUDOCODE
            or ctx.widget_type == idaapi.BWN_DISASM
            else idaapi.AST_DISABLE_FOR_WIDGET
        )


class popup_hooks_t(idaapi.UI_Hooks):
    def __init__(self, action_name):
        idaapi.UI_Hooks.__init__(self)
        self.action_name = action_name

    def finish_populating_widget_popup(self, form, popup):
        widget_type = idaapi.get_widget_type(form)
        if widget_type == idaapi.BWN_PSEUDOCODE or widget_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, self.action_name)


class OutliningPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "Mark functions as outlined in decompiler view"
    help = "Press O to outline the current function"
    wanted_name = "hx_outliner"
    actname = "hx_outliner:make_outlined"
    wanted_hotkey = ""
    hooks = None

    def init(self):
        addon = idaapi.addon_info_t()
        addon.id = "milankovo.ida_outliner"
        addon.name = "functions outliner"
        addon.producer = "Milankovo"
        addon.url = "https://github.com/milankovo/ida_outliner"
        addon.version = "9.00"
        idaapi.register_addon(addon)
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        
        if idaapi.register_action(
            idaapi.action_desc_t(
                self.actname, "Make outlined", outline_func_action_handler_t(), "o"
            )
        ):
            self.hooks = popup_hooks_t(self.actname)
            self.hooks.hook()
        else:
            return idaapi.PLUGIN_SKIP
        
        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.hooks:
            self.hooks.unhook()
        idaapi.unregister_action(self.actname)

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return OutliningPlugin()
