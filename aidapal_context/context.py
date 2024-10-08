import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


class context:
    '''
    This class is a context manager that handles the setting and restoring of the context
    window for aidapal.

    The context window is a comment block that is inserted into the c style comment block
    for each query to the model.
    '''
    context = []

    def __init__(self):
        self.context = []
        logging.debug("Initialized context with an empty list.")

    def add_context(self, context):
        '''
        Add a context string to the context list
        '''
        self.context.append(context)
        logging.debug(f"Added context: {context}")

    def clear_context(self):
        '''
        Clear the context list
        '''
        self.context = []
        logging.debug("Cleared the context list.")

    def get_context(self):
        '''
        Get the context array directly

        returns None if there is no context
        '''
        if len(self.context) == 0:
            logging.debug("No context available.")
            return None
        logging.debug(f"Returning context: {self.context}")
        return self.context
    
    def get_context_comment_block(self):
        '''
        Get the context string as a comment block:
            /* context1
            context2
            */
        returns None if there is no context
        '''
        if len(self.context) == 0:
            logging.debug("No context available for comment block.")
            return None
        cmt_block = '/* '
        cmt_block += '\n'.join([x for x in self.context])
        cmt_block += ' */'
        logging.debug(f"Returning context comment block: {cmt_block}")
        return cmt_block