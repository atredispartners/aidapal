import ida_kernwin,ida_funcs,idaapi,idautils,idc,ida_hexrays,ida_name
import threading,requests,json,zlib
from functools import partial

from idapal_qt_interface import *

# this list holds the list of models registered with Ollama to be accessible from the plugin.
models = ['aidapal']
# where ollama service is running
ollama_url = "http://localhost:11434/api/generate"
# most important part - zlib compressed ascii art
load_logo = b'x\x9c\x8dW[\x8e\xdc0\x0c\xfb\x9fS\x180\xfc#A:\x80\x01\x01\xb9\xff\xa9J\xd2N&3\x9bnk\x14\xeb\x8cc3"\xf5r[\xfb\xd7\xc8\xcc\xc9\x819\xff\xb9\xb9\xbd~\x01\x9aQn\xd6{\x1f{\xe0\xd1\xcc+\xe6/\xc0\x7f\x01\xccp[8\x80\xe8\x00\xc1\xc0\x8a]\x8b\x1e\xf3\xff\x00S`\xdb\xa6nA\xaaX!`\xe0\x01?\xf1v\xa3z<X\xfa\xfa\xc0\xe2\xa8\x13\xcdy\xdaz\xb5\x10U\xfc)\xbc\xd47\xae/\xd6\xc7\xd1O\xc0Y2\x83\xf2C;R\x9aAs\x88P\x16a%|\x01\xe2\x95{\xcd\xb5\x97c\xfe\x04<\xb1\x08\xe6\xd1\x9af\x90\x02\x98yK\xb7\xd9\xf84!\x08Fq\x07\xe7\xd3\x82\xfa\x06L\xfap\xbb0\xf1\x8fN\x08 \x98\xec\x08Z\xa8\xa3Z\n:I\xdb\xce@\x18#[\xdd\x00\xe7\x05\xe8<@\xfb\xa2f\xd2\x16\xae}O0;h#\xd1\xfd\t0e\xa1\xa2A|\'\xfd:\x13\xa7\xca\xeb\x8c\xea5a\x01\xaa\x00\xb1\x12\xdbD\x7f\x85Rn\xd7\xbc\x84\x97\xb3\xd9\xf2,\x00\xa0W1)\x96\xe8\xd9$U2t\x1cb\n\xb88\x979\xa4qy\xfc\xb0\xc6\xf0Z\x80x\xe8\xde\xeaX\x81\xd7\xe6f\x07\x88)\x18hG\xad\xf0\x87\xe2\x07\x85[j\x80,=%\xc0j\xd6\x85(\xca\x10!\xf3\xc4\xf3s\x808\xd1BQ\x020L\x0c$\xc6\xc8\xac\xf7\xa6\x10b&\\pR\xae\x01\xb5\xf0\x17>ny\xee\xc4G\x88 \x82\xd1T\x18bG^\x9b}\xa9-"\r~\x1e\xd5\x10\x13\xc3\t(\x07[\xc3i\xefz\xbbd>8\xfc\xf2\x05-\xbc\xbc\xe3zI\x17b7mP6\xa5\x8f\x010X\xe8\xf0\x05XC\x8e\x90\xdb\x0chC\x16\x80\x0b\xebBnK)\x01\xde\xd2u\xb7]8D<\x03E\x9a\x08\xc0>"+\x8byI\xc2\xfd8\x18\xc3\xa9BX\x9d\xb6 \x941\x8a\x18GW\x04\xb0L\x84\xe1\x97H\x03+\xa6\xcf\x18\x9d\x80\xd9\x07\xcb\x00\x0c\x96\x81@\xc0\x07\x01\xda\xf0\x1e~\xb3\xe3c@x\x1c\x88\x86\xe5@d\x10\x11\xc7`\x1b\xfc\xe5<\xf0\xa2\xc20\xd5F\x87\x02`\xc43\xfc\xbc,dH\x8d;\xde`8\xcbB\x91 \x1b\xa88q\xd8(\x1d \x04H{\x8b\xf0%\xc2\x90\xec\xccp\x1c\xfa\x04d\x0e\xec\x81o\x92t\x11pQf`\x88r\xc9\xde\xc1T\x02 f\xf0\x90j\x08\xb3\xfa\xa4\x0c9\\\x8aB\x1d\x00\x91s\x10\x90\x10\xd5E\x19l7\xa0\x8b>\x10c\xd5(V\xbc\x15"\xa6!\x13Y\x19|U\xb6\x1a\n\x9e$Y\x01\x82w{!^\xc7\x94\x8b\x06#G\x888v\xf3+3\x95\xe5\xcf\xf8\xf4\xf6\xb9\xebGW\x0c.\xca\x13\xceb\x1c6v!5\xb7\x8d8p\xc8\xde\xd29\xaa\x85O\xd5\x82\xb7\xcb\xb5cl<\x0eB\xc0\xc0\x82\x86 \x8a\x0fD\xa4\xb1GLV\xb7\xde\xef\xbau\x861\x83\xf8s\x95\xdb\x98[\xf0f\xc0\xe7\xb2\'Wq \x7fv\x11\xf4\'\x95\x87\xab\x15\x1f\x8f\xe3\xec\xd1\x9d\xa5AQ\x0c\x03\xa7J\xeeY\xb1s\x95w\xe8\x8c\x92T\xaau\xe21\x1e\xc7\xa2Xl\x14\xec2\x93M\x01Oy\xef)ij\x92\xa1\xa8\xe7\xe6Fg\xda\x82\xfd\x1a\xc6.\x0f\xa1X\t;\x9b8\xd2\x18V\xcc\xaf&U\xd4\x1d\x11\x8d\x84\x03qU.f\n\x93&V\xab\xa4s\xafEl0\x9a\xca\xd2K\xbaW\xb8\x9f\x16\xae\xb4\x88e\x93\xb3\xa7\xa8\xfd\x11c\xa5E\xac\xcc\xe1\x02%\x81\x0f\x19~]\x9c\xa5^~7z\x16\x8d\xc5\x89x\xeb\xc0\xb1c\x99B\xb0\xf0\x9d\x0b\xe7\x06\xe9\xdc\xa3\xdd\xc6\xe7\xddF\xce\x80\xba2,\xb6\x9b\r\xf1\xaa<B&l\x1f#\x14\xb0\x85Y+\xbd\xff\x0e(\xcc\xa9;Q\xb29\xb3\xdd\x97l/\xde\rX=$fk\xab!\xce\xfaq\x07\xbb\x03\xe6\xbd\x01\xef\x1b\xe6\xfb\xb2y]:\xdf\x1b\xce)\x1f\x01SN\xacu\x07\xa2Ot\xbb\xd9}\x89a\xcfHUUXO\xd7\xbe)=\x7fzY_g\x91D\xe7E\xd2"\xc8\x99s]%\xbf\xb3vr>\xd0\x97\x86\xa1]c\x01\x9d;\xe3\xb0e\xf4\x93\x97\x89\x87\xba2\x80E@TB\xf4\x9c\x89"\x8d_\x8e{\xc0\x14 \xd2\xda\x813P|\xfc\r\xf8d![\xd2a\xeau!\xc0\x80\x85p:\x8b\x06\x99"+\xd8M\x18\x87\xa1\xc6gG\x11\xd9x#\xc9\x07\x0b\x95\x00\xfaZ\xcc\xf5\xb4\xa3x/\xcf\xb86\xf0q\xaf\xef=\x0fN\xf9\x8f\xff1\xfc6\xae\xe3\xaf?\xc7\xe9%\xd5'
print(zlib.decompress(load_logo).decode('ascii'))

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
        print(f'aidapal: error unpacking response')
        print(res.json()['response'])
        

def do_show_ui(result,cur_func):
    aiDAPalUI(result,cur_func)
    return False

def async_call(cur_func,model_name,extra_context=None):
    code = str(cur_func)
    if extra_context:
        code = f'{extra_context}\n{code}'
    result = do_analysis(code,model_name)
    if result:
        call_do_show_ui = partial(do_show_ui,result,cur_func)
        #print(result)
        
        # update the function with the results
        ida_kernwin.execute_ui_requests([call_do_show_ui,])


def get_references_from_function(func_ea):
    '''
    walks a function extracting out a unique list of data reference addresses
    '''
    # List to hold the references found
    refs = []

    # Get the function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        return refs

    # Iterate over all the heads (instructions or data) in the function
    for head_ea in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head_ea)):
            # data references from this instruction
            refs_from = idautils.DataRefsFrom(head_ea)
            for ref in refs_from:
                refs.append(ref)
                print(f'{hex(ref)}')
    # return unique values
    return set(refs)

def get_function_data_ref_comments(current_func_ea):
    '''
    extracts string that is a c style comment block of comments for any data refs that
    have a comment
    '''
    if current_func_ea is not None:
        # Get references from the current function - returns a set of them
        references = get_references_from_function(current_func_ea)
        data_comments = '/*\n'
        for ref in references:
            cmt = ''
            cmt_1 = idc.get_cmt(ref,1)
            if cmt_1:
                cmt = cmt_1
            cmt_0 = idc.get_cmt(ref,0)
            if cmt_0:
                cmt += f' {cmt_0}'
            name = ida_name.get_name(ref)
            if cmt.strip() != '':
                dcmt = f'{name}: {cmt.strip()}\n'
                data_comments += dcmt
        data_comments += '*/'
        return data_comments
    else:
        print("No function at the current address.")
        return None


class MyActionHandler(ida_kernwin.action_handler_t):
    model = ''
    def __init__(self,model):
        self.model = model
        ida_kernwin.action_handler_t.__init__(self)

    # This method is called when the menu item is clicked
    def activate(self, ctx):
        # get the current function code
        cur_func = ida_hexrays.decompile(idaapi.get_screen_ea())
        print(f'aiDAPal started for {cur_func.entry_ea}')
        dref_comments = get_function_data_ref_comments(cur_func.entry_ea)
        if dref_comments == "/*\n*/":
            dref_comments = None
        print(f'aiDAPal: extra juice {dref_comments}')
        caller = partial(async_call,cur_func,self.model,dref_comments)
        threading.Thread(target=caller).start()

    # This method is used to update the state of the action (optional)
    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS
        
for model in models:
    action_desc = ida_kernwin.action_desc_t(
        model,   # The unique name of the action
        f'aiDAPal:{model}', # The label of the menu item
        MyActionHandler(model),    # The action handler class
        None,                 # Optional shortcut key
        f'Uses {model}', # Tooltip
        199)                  # Optional icon ID
    ida_kernwin.register_action(action_desc)


class MyHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        # Check if the widget is the disassembly view
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            for model in models:
                ida_kernwin.attach_action_to_popup(widget, popup_handle, model, None)

# Create an instance and install
hooks = MyHooks()
hooks.hook()
