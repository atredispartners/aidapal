import ida_funcs
import idautils
import idc
import ida_bytes
import ida_name
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def get_all_comments(ea):
    '''
    Helper to return both repeatable and non repeatable comments for a given address
    returns empty string if no comment
    '''
    cmt = ida_bytes.get_cmt(ea,False)
    r_cmt = ida_bytes.get_cmt(ea,True)
    if cmt is None:
        if r_cmt is None:
            return ''
        return r_cmt
    return f'{cmt} - {r_cmt}'
    

def gather_unique_data_references(function_ea):
    '''
    Function to gather unique data references in a given function
    returns a list of unique data references or empty list if none found
    '''
    try:
        # Get the function object
        func = ida_funcs.get_func(function_ea)
        if not func:
            logging.error(f"Invalid function address: 0x{function_ea:X}")
            return []

        # Create a set to store unique data references
        data_references = []

        # Iterate over all instructions in the function
        for head in idautils.FuncItems(function_ea):
            # Get all cross-references from the current instruction
            for xref in idautils.DataRefsFrom(head):
                logging.debug(f"Xref from 0x{head:X} to 0x{xref:X} flags: {hex(idc.get_full_flags(xref))} name: {ida_name.get_name(xref)}")
                # Ignore targets that have no flags - skip addresses to local type/struct
                if not idc.get_full_flags(xref):
                    logging.debug(f"Skipping 0x{xref:X} due to no flags")
                    continue
            
                # Ignore offsets or invalid xrefs (immediates)
                if idc.get_operand_type(head, 0) in (idc.o_displ, idc.o_imm):
                    logging.debug(f"Skipping 0x{xref:X} due to operand type")
                    continue
                
                # Get name of the target address if it exists
                name = ida_name.get_name(xref)
                data_info = ''
                
                # Ignore default named items sub_,off_,dword_etc, keep unamed items
                if not ida_name.is_uname(name) and name != '':
                    logging.debug(f"Skipping 0x{xref:X} due to default name {name}")
                    continue
                    
                    
                # Get regular and repeatable comments at the target address
                comment = get_all_comments(xref)
                data_info += f'{hex(xref)} is {name} // {comment}'

                # Check if the given address is a tail- this means its part of a larger data object
                # either a struct or array
                if idc.is_tail(idc.get_full_flags(xref)):
                    # Get the head address
                    head_addr = idc.get_item_head(xref)
                    

                    # Check if the head is a structure - get info from it
                    if idc.is_struct(idc.get_full_flags(head_addr)):
                        # Get struct instance name
                        struct_instance_name = idc.get_name(head_addr)
                        # Get structure ID from head address
                        struct_name = idc.get_type(head_addr)
                        struc_id = idc.get_struc_id(struct_name)
                        
                        # Get offset into structure for current address
                        member_offset = xref - head_addr 
                        # Get the structure member ID
                        member_id = idc.get_member_id(struc_id,member_offset)
                        
                        if struc_id != idc.BADADDR:
                            # Get the structure member name, size, and comment
                            member_name = (idc.get_member_name(struc_id,member_offset) or "undefined")
                            member_size = idc.get_member_size(struc_id,member_offset) or 0
                            member_cmt = (idc.get_member_cmt(struc_id,member_offset,False) or "") + (idc.get_member_cmt(struc_id,member_offset,True) or "")
                            data_info = f'0x{xref:X} is {struct_instance_name}->{member_name} //size:0x{member_size:x} cmt:{member_cmt} struct_type:{struct_name}'
                            
                    # Its not a struct - get the head name and comment if it exists
                    else:
                        # Check if the head has a name or comment
                        head_name = idc.get_name(head_addr)
                        head_comment = get_all_comments(head_addr)
                        data_offset = xref - head_addr
                        if head_name or head_comment:
                            data_info = f"0x{xref:X} is part of data @ 0x{head_addr:X}:"
                            if head_name:
                                data_info += f" {head_name}[{hex(data_offset)}]"
                            if head_comment:
                                data_info += f" //{head_comment}"
                
                # Store the details (origin instruction, xref, name, comments)
                data_references.append(data_info)

        # Convert the set to a list and return the unique references
        unique_data_references = set(data_references)
        return unique_data_references

    except Exception as e:
        print(f"An error occurred: {e}")
        return []

"""def main():
    # Get the current address of the cursor
    current_ea = ida_kernwin.get_screen_ea()
    if current_ea is None or current_ea == idc.BADADDR:
        print("Unable to get the current address.")
        return

    # Get the function start address using the current cursor address
    function_ea = ida_funcs.get_func(current_ea).start_ea

    # Gather unique data references
    unique_refs = gather_unique_data_references(function_ea)

    if unique_refs:
        print(f"Unique data references in function at 0x{function_ea:X}:")
        for ref in unique_refs:
            print(ref)
    else:
        print(f"No data references found in function at 0x{function_ea:X}.")

# Run the script
main()"""