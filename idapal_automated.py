#Modified to add automation and some other code on 8/16/2024. Hope it helps someone some day.
#Best,
#-Me

import ida_kernwin, ida_funcs, idaapi, idautils, idc, ida_hexrays, ida_name
import threading, requests, json, zlib, logging, textwrap
from functools import partial
from idapal_qt_interface import aiDAPalUIForm

# Initialize logging
logging.basicConfig(filename='aidapal.log', level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s')

models = ['aidapal']
ollama_url = "http://localhost:11434/api/generate"
funcXFromArray = []

def find_and_sort_functions_by_calls():
    global funcXFromArray
    logging.info("Starting to find and sort functions by calls...")
    func_call_count = {}
    for func in idautils.Functions():
        try:
            func_obj = ida_funcs.get_func(func)
            if func_obj is None:
                continue
            logging.debug(f"Analyzing function at address: {hex(func_obj.start_ea)}")
            call_count = sum(1 for head_ea in idautils.Heads(func_obj.start_ea, func_obj.end_ea) 
                             if idc.is_code(idc.get_full_flags(head_ea)) and idaapi.is_call_insn(head_ea))
            if call_count > 0:
                func_call_count[func_obj.start_ea] = call_count
                logging.debug(f"Function at {hex(func_obj.start_ea)} has {call_count} calls.")
            else:
                logging.debug(f"Function at {hex(func_obj.start_ea)} has no calls.")
        except Exception as e:
            logging.error(f"Error analyzing function at address {hex(func)}: {str(e)}")

    funcXFromArray = sorted(func_call_count.keys(), key=lambda x: func_call_count[x])
    logging.info(f"Sorted functions by calls: {funcXFromArray}")

find_and_sort_functions_by_calls()

def do_analysis(code, model_name):
    url = ollama_url
    headers = {"Content-Type": "application/json"}
    payload = {"model": model_name, "prompt": code, "stream": False, "format": "json"}

    try:
        logging.info(f"Sending code to {model_name} model for analysis...")
        res = requests.post(url, headers=headers, json=payload)
        res.raise_for_status()
        t = res.json()['response']
        t = json.loads(t)
        logging.info("Successfully received analysis results.")
        return t
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to {ollama_url} failed: {str(e)}")
    except ValueError as ve:
        logging.error(f"Failed to decode JSON response: {str(ve)}")
    except Exception as e:
        logging.error(f"Unexpected error during analysis: {str(e)}")
    return None

def apply_changes_main_thread(result, cur_func):
    try:
        if result.get('function_name'):
            new_name = f"{result['function_name']}_{hex(cur_func.entry_ea)[2:]}"
            if ida_name.set_name(cur_func.entry_ea, new_name, ida_name.SN_CHECK):
                logging.info(f"Successfully updated function name to {new_name} for {hex(cur_func.entry_ea)}.")
            else:
                logging.warning(f"Failed to update function name for {hex(cur_func.entry_ea)}.")
        
        if result.get('comment'):
            new_comment = '\n'.join(textwrap.wrap(result['comment'], width=80))
            cf = ida_funcs.get_func(cur_func.entry_ea)
            if ida_funcs.set_func_cmt(cf, new_comment, False):
                logging.info(f"Successfully updated comment for function at {hex(cur_func.entry_ea)}.")
            else:
                logging.warning(f"Failed to update comment for function at {hex(cur_func.entry_ea)}.")
        
        if 'variables' in result:
            for var in result['variables']:
                if var.get('accepted', True):
                    original_name = var['original_name']
                    new_name = var['new_name']
                    if ida_hexrays.rename_lvar(cur_func.entry_ea, original_name, new_name):
                        logging.info(f"Successfully renamed variable {original_name} to {new_name} in function {hex(cur_func.entry_ea)}.")
                    else:
                        logging.warning(f"Failed to rename variable {original_name} in function {hex(cur_func.entry_ea)}.")
        
        cur_func.refresh_func_ctext()
        logging.info(f"Successfully applied changes to function at {hex(cur_func.entry_ea)}.")
    except Exception as e:
        logging.error(f"Failed to apply changes to function at {hex(cur_func.entry_ea)}: {str(e)}")

def apply_changes(result, cur_func):
    ida_kernwin.execute_sync(lambda: apply_changes_main_thread(result, cur_func), ida_kernwin.MFF_FAST)

def async_call(cur_func, model_name, extra_context=None):
    try:
        logging.info(f"Starting analysis for function at address {hex(cur_func.entry_ea)}.")
        code = str(cur_func)
        if extra_context:
            code = f'{extra_context}\n{code}'
            logging.debug(f"Extra context provided for analysis: {extra_context}")
        result = do_analysis(code, model_name)
        if result:
            apply_changes(result, cur_func)
        else:
            logging.warning(f"No valid result for function at {hex(cur_func.entry_ea)}.")
    except Exception as e:
        logging.error(f"Error in async_call for function {hex(cur_func.entry_ea)}: {str(e)}")

def get_references_from_function(func_ea):
    refs = []
    try:
        func = ida_funcs.get_func(func_ea)
        if not func:
            return refs
        logging.debug(f"Extracting references from function at {hex(func.start_ea)}")
        for head_ea in idautils.Heads(func.start_ea, func.end_ea):
            if idc.is_code(idc.get_full_flags(head_ea)):
                refs_from = idautils.DataRefsFrom(head_ea)
                for ref in refs_from:
                    refs.append(ref)
                    logging.debug(f"Found reference at {hex(ref)}")
    except Exception as e:
        logging.error(f"Error extracting references from function at {hex(func_ea)}: {str(e)}")
    return set(refs)

def get_function_data_ref_comments(current_func_ea):
    try:
        logging.debug(f"Getting data reference comments for function at {hex(current_func_ea)}")
        if current_func_ea is not None:
            references = get_references_from_function(current_func_ea)
            data_comments = '/*\n'
            for ref in references:
                cmt = ''
                cmt_1 = idc.get_cmt(ref, 1)
                if cmt_1:
                    cmt = cmt_1
                cmt_0 = idc.get_cmt(ref, 0)
                if cmt_0:
                    cmt += f' {cmt_0}'
                name = ida_name.get_name(ref)
                if cmt.strip() != '':
                    dcmt = f'{name}: {cmt.strip()}\n'
                    data_comments += dcmt
            data_comments += '*/'
            logging.debug(f"Extracted comments: {data_comments}")
            return data_comments
        else:
            logging.warning("No function at the current address.")
            return "/* No comments */"
    except Exception as e:
        logging.error(f"Error getting data ref comments for function at {hex(current_func_ea)}: {str(e)}")
        return "/* Error in comments */"

class MyActionHandler(ida_kernwin.action_handler_t):
    model = ''
    def __init__(self, model):
        self.model = model
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        try:
            for func_ea in funcXFromArray:
                logging.info(f"Processing function at address {hex(func_ea)}")
                cur_func = ida_hexrays.decompile(func_ea)
                if cur_func:
                    logging.info(f"Decompiled function at {hex(cur_func.entry_ea)}")
                    dref_comments = get_function_data_ref_comments(cur_func.entry_ea)
                    if dref_comments == "/*\n*/":
                        dref_comments = None
                    logging.debug(f"Extra data comments: {dref_comments}")
                    caller = partial(async_call, cur_func, self.model, dref_comments)
                    self.update(ctx)
                    logging.info(f"Starting analysis for {hex(cur_func.entry_ea)}")
                    threading.Thread(target=caller).start()
                    logging.info(f"Analysis started for {hex(cur_func.entry_ea)}")
                else:
                    logging.warning(f"Failed to decompile function at address {hex(func_ea)}")
        except Exception as e:
            logging.error(f"Error in MyActionHandler.activate: {str(e)}")

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

for model in models:
    action_desc = ida_kernwin.action_desc_t(
        model, f'aiDAPal:{model}', MyActionHandler(model), None,
        f'Uses {model}', 199)
    ida_kernwin.register_action(action_desc)

class MyHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            for model in models:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, model, None)

hooks = MyHooks()
hooks.hook()

if __name__ == '__main__':
    handler = MyActionHandler(models[0])
    handler.activate(None)
    logging.info("Completed processing all functions.")
