import ida_kernwin
import ida_funcs
import idaapi
import idautils
import idc
import ida_hexrays
import ida_name
import ida_lines

import threading,requests,json,zlib
from functools import partial

# this is the UI class that is used to display the results of the analysis
from idapal_qt_interface import *

# context helper to manage the context for the plugin
from aidapal_context import context

# helper to extract information about the current target to inject into the context at runtime
from aidapal_helpers import context_juicer

import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# this list holds the list of models registered with Ollama to be accessible from the plugin.
models = ['aidapal','llamapal31q8']
# where ollama service is running
ollama_url = "http://127.0.0.1:11434/api/generate"
# most important part - zlib compressed ascii art
load_logo = b'x\x9c\x8dW[\x8e\xdc0\x0c\xfb\x9fS\x180\xfc#A:\x80\x01\x01\xb9\xff\xa9J\xd2N&3\x9bnk\x14\xeb\x8cc3"\xf5r[\xfb\xd7\xc8\xcc\xc9\x819\xff\xb9\xb9\xbd~\x01\x9aQn\xd6{\x1f{\xe0\xd1\xcc+\xe6/\xc0\x7f\x01\xccp[8\x80\xe8\x00\xc1\xc0\x8a]\x8b\x1e\xf3\xff\x00S`\xdb\xa6nA\xaaX!`\xe0\x01?\xf1v\xa3z<X\xfa\xfa\xc0\xe2\xa8\x13\xcdy\xdaz\xb5\x10U\xfc)\xbc\xd47\xae/\xd6\xc7\xd1O\xc0Y2\x83\xf2C;R\x9aAs\x88P\x16a%|\x01\xe2\x95{\xcd\xb5\x97c\xfe\x04<\xb1\x08\xe6\xd1\x9af\x90\x02\x98yK\xb7\xd9\xf84!\x08Fq\x07\xe7\xd3\x82\xfa\x06L\xfap\xbb0\xf1\x8fN\x08 \x98\xec\x08Z\xa8\xa3Z\n:I\xdb\xce@\x18#[\xdd\x00\xe7\x05\xe8<@\xfb\xa2f\xd2\x16\xae}O0;h#\xd1\xfd\t0e\xa1\xa2A|\'\xfd:\x13\xa7\xca\xeb\x8c\xea5a\x01\xaa\x00\xb1\x12\xdbD\x7f\x85Rn\xd7\xbc\x84\x97\xb3\xd9\xf2,\x00\xa0W1)\x96\xe8\xd9$U2t\x1cb\n\xb88\x979\xa4qy\xfc\xb0\xc6\xf0Z\x80x\xe8\xde\xeaX\x81\xd7\xe6f\x07\x88)\x18hG\xad\xf0\x87\xe2\x07\x85[j\x80,=%\xc0j\xd6\x85(\xca\x10!\xf3\xc4\xf3s\x808\xd1BQ\x020L\x0c$\xc6\xc8\xac\xf7\xa6\x10b&\\pR\xae\x01\xb5\xf0\x17>ny\xee\xc4G\x88 \x82\xd1T\x18bG^\x9b}\xa9-"\r~\x1e\xd5\x10\x13\xc3\t(\x07[\xc3i\xefz\xbbd>8\xfc\xf2\x05-\xbc\xbc\xe3zI\x17b7mP6\xa5\x8f\x010X\xe8\xf0\x05XC\x8e\x90\xdb\x0chC\x16\x80\x0b\xebBnK)\x01\xde\xd2u\xb7]8D<\x03E\x9a\x08\xc0>"+\x8byI\xc2\xfd8\x18\xc3\xa9BX\x9d\xb6 \x941\x8a\x18GW\x04\xb0L\x84\xe1\x97H\x03+\xa6\xcf\x18\x9d\x80\xd9\x07\xcb\x00\x0c\x96\x81@\xc0\x07\x01\xda\xf0\x1e~\xb3\xe3c@x\x1c\x88\x86\xe5@d\x10\x11\xc7`\x1b\xfc\xe5<\xf0\xa2\xc20\xd5F\x87\x02`\xc43\xfc\xbc,dH\x8d;\xde`8\xcbB\x91 \x1b\xa88q\xd8(\x1d \x04H{\x8b\xf0%\xc2\x90\xec\xccp\x1c\xfa\x04d\x0e\xec\x81o\x92t\x11pQf`\x88r\xc9\xde\xc1T\x02 f\xf0\x90j\x08\xb3\xfa\xa4\x0c9\\\x8aB\x1d\x00\x91s\x10\x90\x10\xd5E\x19l7\xa0\x8b>\x10c\xd5(V\xbc\x15"\xa6!\x13Y\x19|U\xb6\x1a\n\x9e$Y\x01\x82w{!^\xc7\x94\x8b\x06#G\x888v\xf3+3\x95\xe5\xcf\xf8\xf4\xf6\xb9\xebGW\x0c.\xca\x13\xceb\x1c6v!5\xb7\x8d8p\xc8\xde\xd29\xaa\x85O\xd5\x82\xb7\xcb\xb5cl<\x0eB\xc0\xc0\x82\x86 \x8a\x0fD\xa4\xb1GLV\xb7\xde\xef\xbau\x861\x83\xf8s\x95\xdb\x98[\xf0f\xc0\xe7\xb2\'Wq \x7fv\x11\xf4\'\x95\x87\xab\x15\x1f\x8f\xe3\xec\xd1\x9d\xa5AQ\x0c\x03\xa7J\xeeY\xb1s\x95w\xe8\x8c\x92T\xaau\xe21\x1e\xc7\xa2Xl\x14\xec2\x93M\x01Oy\xef)ij\x92\xa1\xa8\xe7\xe6Fg\xda\x82\xfd\x1a\xc6.\x0f\xa1X\t;\x9b8\xd2\x18V\xcc\xaf&U\xd4\x1d\x11\x8d\x84\x03qU.f\n\x93&V\xab\xa4s\xafEl0\x9a\xca\xd2K\xbaW\xb8\x9f\x16\xae\xb4\x88e\x93\xb3\xa7\xa8\xfd\x11c\xa5E\xac\xcc\xe1\x02%\x81\x0f\x19~]\x9c\xa5^~7z\x16\x8d\xc5\x89x\xeb\xc0\xb1c\x99B\xb0\xf0\x9d\x0b\xe7\x06\xe9\xdc\xa3\xdd\xc6\xe7\xddF\xce\x80\xba2,\xb6\x9b\r\xf1\xaa<B&l\x1f#\x14\xb0\x85Y+\xbd\xff\x0e(\xcc\xa9;Q\xb29\xb3\xdd\x97l/\xde\rX=$fk\xab!\xce\xfaq\x07\xbb\x03\xe6\xbd\x01\xef\x1b\xe6\xfb\xb2y]:\xdf\x1b\xce)\x1f\x01SN\xacu\x07\xa2Ot\xbb\xd9}\x89a\xcfHUUXO\xd7\xbe)=\x7fzY_g\x91D\xe7E\xd2"\xc8\x99s]%\xbf\xb3vr>\xd0\x97\x86\xa1]c\x01\x9d;\xe3\xb0e\xf4\x93\x97\x89\x87\xba2\x80E@TB\xf4\x9c\x89"\x8d_\x8e{\xc0\x14 \xd2\xda\x813P|\xfc\r\xf8d![\xd2a\xeau!\xc0\x80\x85p:\x8b\x06\x99"+\xd8M\x18\x87\xa1\xc6gG\x11\xd9x#\xc9\x07\x0b\x95\x00\xfaZ\xcc\xf5\xb4\xa3x/\xcf\xb86\xf0q\xaf\xef=\x0fN\xf9\x8f\xff1\xfc6\xae\xe3\xaf?\xc7\xe9%\xd5'
print(zlib.decompress(load_logo).decode('ascii'))

aidapal_manual_juice = []

def aidapal_add_context(context_value):
    '''
    This function is used to manually add to the global context var aidapal_manual_juice
    '''
    aidapal_manual_juice.append(f"{context_value}")

def aidapal_get_context():
    '''
    print the current manual context
    '''
    outstr = ''
    for x in aidapal_manual_juice:
        outstr += f'{x}\n'
    return outstr

def do_analysis(code,model_name):
    url = ollama_url
    headers = {"Content-Type": "application/json"}
    payload = {"model": model_name, "prompt": code, "stream": False,"format":"json"}
    res = requests.post(url, headers=headers, json=payload)
    try:
        t = res.json()['response']
        t = json.loads(t)
        return t
    except:
        # rarely this occurs, leftover from early on
        logging.error(f'aiDAPal: error unpacking response\n{res.json()["response"]}')
        return None
        

def do_show_ui(result,cur_func,data_address):
    aiDAPalUI(result,cur_func,data_address)
    return False


# examples/core/dump_selection.py
def get_hexrays_selection():
    '''
    get highlighted text from the hexrays view
    return None if no selection
    '''
    # dump current selection
    p0 = ida_kernwin.twinpos_t()
    p1 = ida_kernwin.twinpos_t()
    view = ida_kernwin.get_current_viewer()
    logging.debug(f'aiDAPal: getting hexrays selection')
    if ida_kernwin.read_selection(view, p0, p1):
        lines = get_widget_lines(view, p0, p1)
        logging.debug("\n".join(lines))
        return "\n".join(lines)
    return None

def get_widget_lines(widget, tp0, tp1):
    """
    get lines between places tp0 and tp1 in widget
    """
    ud = ida_kernwin.get_viewer_user_data(widget)
    lnar = ida_kernwin.linearray_t(ud)
    lnar.set_place(tp0.at)
    lines = []
    while True:
        cur_place = lnar.get_place()
        first_line_ref = ida_kernwin.l_compare2(cur_place, tp0.at, ud)
        last_line_ref = ida_kernwin.l_compare2(cur_place, tp1.at, ud)
        if last_line_ref > 0: # beyond last line
            break
        line = ida_lines.tag_remove(lnar.down())
        if last_line_ref == 0: # at last line
            line = line[0:tp1.x]
        elif first_line_ref == 0: # at first line
            line = ' ' * tp0.x + line[tp0.x:]
        lines.append(line)
    return lines


def async_call(cur_func,model_name,extra_context=None,selected_code=None,data_address=None):
    # if we have a selection, get the selection, otherwise use the whole function
    logging.debug(f'aiDAPal: async call {model_name}')
    if selected_code:
        logging.debug('aiDAPal: selection')
        code = selected_code
    else:
        code = str(cur_func)
    logging.debug(f'aiDAPal: {code}')
    if extra_context:
        code = f'{extra_context}\n{code}'
    result = do_analysis(code,model_name)
    if result:
        call_do_show_ui = partial(do_show_ui,result,cur_func,data_address)
        #print(result)
        
        # update the function with the results
        ida_kernwin.execute_ui_requests([call_do_show_ui,])


def get_data_references_query(target_data_ea):
    results = []
    query = ''
    target_data_name = ida_name.get_name(target_data_ea)
    # Ensure the decompiler is available
    if not ida_hexrays.init_hexrays_plugin():
        logging.error(f'aiDAPal: Hex-Rays decompiler is not available.')
        return results
    
    target_xrefs = []
    xrefs = idautils.XrefsTo(target_data_ea)
    for xref in xrefs:
        #get a reference to the function
        curfunc = ida_funcs.get_func_name(xref.frm)
        curfunc_t = ida_funcs.get_func(xref.frm)
        if curfunc:
            target_xrefs.append(curfunc_t.start_ea)

    # Iterate through all functions in the binary
    for ea in set(target_xrefs):
        func_name = ida_funcs.get_func_name(ea)
        
        try:
            # Decompile the function
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                logging.error(f'aiDAPal: failed to decompile function at {hex(ea)}')
                continue

            # Get the decompiled code as text
            decompiled_text = cfunc.get_pseudocode()
            #print(f'decompiled {hex(ea)}')
            # Search for the target function name in each line
            for line_number, line in enumerate(decompiled_text, 1):
                # Remove tags to get clean text
                line_text = ida_lines.tag_remove(line.line)
                
                if target_data_name in line_text:
                    #print(f'{target_func_name} - {line_text}')
                    results.append((func_name, line_number, line_text.strip()))
        
        except ida_hexrays.DecompilationFailure as e:
            logging.error(f'aiDAPal: decompilation failed for function at {hex(ea)}: {str(e)}')

    if results:
        query = f'/* {target_data_name} is referenced in the following locations:\n'
        # Build the query
        if results:
            for ref in results:
                query += f'in function {ref[0]}: {ref[2]}\n'
            query += f'*/\n{target_data_name}'
    return query

def get_function_data_ref_comments(current_func_ea):
    '''
    extracts string that is a c style comment block of comments for any data refs that
    have a comment
    '''
    if current_func_ea is not None:
        # Get references from the current function - returns a set of them
        #references = get_references_from_function(current_func_ea)
        logging.info(f'aiDAPal: gathering data references for {hex(current_func_ea)}')
        references = context_juicer.gather_unique_data_references(current_func_ea)
        # inject our manual defines into the comment block
        data_comments = f'/*{aidapal_get_context()}\n'
        for ref in references:
                data_comments += f'{ref}\n'
        data_comments += '*/'
        return data_comments
    else:
        logging.error(f'aiDAPal: no function at current address')
        return None


class FunctionDecompilerHandler(ida_kernwin.action_handler_t):
    model = ''
    selection = False
    def __init__(self,model,selection=False):
        self.model = model
        self.selection = selection
        logging.debug(f'aiDAPal: {model} {selection}')
        ida_kernwin.action_handler_t.__init__(self)

    # This method is called when the menu item is clicked
    def activate(self, ctx):
        # get the current function code
        cur_func = ida_hexrays.decompile(idaapi.get_screen_ea())
        if cur_func is None:
            logging.error(f'aiDAPal: not currently in a function - is ida view synced with hexrays view?')
            return
        sel_code = None
        if self.selection:
            sel_code = get_hexrays_selection()
            if sel_code is None:
                logging.error(f'aiDAPal: no selection')
                return
        logging.info(f'aiDAPal: starting analysis for {cur_func.entry_ea}')
        dref_comments = get_function_data_ref_comments(cur_func.entry_ea)
        if dref_comments == "/*\n*/":
            dref_comments = None
        logging.info(f'aiDAPal: extra juice {dref_comments}')
        logging.debug(f'aiDAPal: model {self.model} selection {self.selection}')
        caller = partial(async_call,cur_func,self.model,extra_context=dref_comments,selected_code=sel_code)
        threading.Thread(target=caller).start()

    # This method is used to update the state of the action (optional)
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class DataAnalysisHandler(ida_kernwin.action_handler_t):
    model = ''
    selection = False
    def __init__(self,model,selection=False):
        self.model = model
        self.selection = selection
        logging.debug(f'aiDAPal: data analysis {model} {selection}')
        ida_kernwin.action_handler_t.__init__(self)

    # This method is called when the menu item is clicked
    def activate(self, ctx):
        # get the current location address and name
        cur_addr = idaapi.get_screen_ea()
        # Is the current address code or data
        if ida_bytes.is_code(ida_bytes.get_full_flags(cur_addr)):
            logging.error(f'aiDAPal: data analysis called on code')
            return
        cur_name = ida_name.get_name(cur_addr)
        logging.info(f'aiDAPal started for {cur_name} at {hex(cur_addr)}')
        data_query = get_data_references_query(cur_addr)
        if data_query == '':
            logging.error(f'aiDAPal: no data references found')
            return
        logging.debug(f'aiDAPal: model {self.model} selection {self.selection}')
        # Pass None for cur_func as we are working with data
        caller = partial(async_call,None,self.model,extra_context=None,selected_code=data_query,data_address=cur_addr)
        threading.Thread(target=caller).start()

    # This method is used to update the state of the action (optional)
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS



code_actions = []
data_actions = []
for model in models:
    # Register the full function analysis actions
    action_id = f'{model}_ff'
    code_actions.append(action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,   # The unique name of the action
        f'Full Function', # The label of the menu item
        FunctionDecompilerHandler(model),    # The action handler class
        None,                 # Optional shortcut key
        f'Full Function using {model}', # Tooltip
        199)                  # Optional icon ID
    ida_kernwin.register_action(action_desc)

    # Register the selection analysis actions
    action_id = f'{model}_sel'
    code_actions.append(action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,   # The unique name of the action
        f'Selection', # The label of the menu item
        FunctionDecompilerHandler(model,selection=True),    # The action handler class
        None,                 # Optional shortcut key
        f'Selection using {model}', # Tooltip
        199)                  # Optional icon ID
    ida_kernwin.register_action(action_desc)

    # Register the data reference analysis actions
    action_id = f'{model}_data'
    data_actions.append(action_id)
    action_desc = ida_kernwin.action_desc_t(
        action_id,   # The unique name of the action
        f'Data', # The label of the menu item
        DataAnalysisHandler(model,selection=True),    # The action handler class
        None,                 # Optional shortcut key
        f'Data using {model}', # Tooltip
        199)                  # Optional icon ID
    ida_kernwin.register_action(action_desc)


class MyHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        # Check if the widget is the disassembly view
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            for action in code_actions:
                model_name = action.split('_')[0]
                ida_kernwin.attach_action_to_popup(widget, popup_handle, action, f'aiDAPal/{model_name}/')
        # Check if the widget is the disassembly view
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            for action in data_actions:
                model_name = action.split('_')[0]
                ida_kernwin.attach_action_to_popup(widget, popup_handle, action, f'aiDAPal/{model_name}/')

# Create an instance and install
hooks = MyHooks()
hooks.hook()

def unload_plugin():
    for model in models:
        ida_kernwin.unregister_action(model)
    print("aiDAPal unloaded")
    global hooks
    if  hooks is not None:
        hooks.unhook()
        hooks = None