"""
Author: Milankovo, 2025
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


class OutliningPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "TODO"
    help = "TODO"
    wanted_name = "hx_outliner"
    actname = "hx_outliner:make_outlined"
    wanted_hotkey = ""

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
        action = idaapi.action_desc_t(
            self.actname, "make outlined", outline_func_action_handler_t(), "s"
        )
        idaapi.register_action(action)
        return idaapi.PLUGIN_KEEP

    def term(self):
        idaapi.unregister_action(self.actname)
        pass

    def run(self, arg):
        pass


def PLUGIN_ENTRY():
    return OutliningPlugin()
