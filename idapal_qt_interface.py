"""
summary: adding PyQt5 widgets into an `ida_kernwin.PluginForm`

description:
  Using `ida_kernwin.PluginForm.FormToPyQtWidget`, this script
  converts IDA's own dockable widget into a type that is
  recognized by PyQt5, which then enables populating it with
  regular Qt widgets.
"""

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget,QScrollArea
from PyQt5.QtGui import QPalette, QColor
import textwrap

import ida_kernwin,ida_hexrays,ida_funcs,ida_name

example_input = {'function_name': 'ExampleName', 'comment': "Example Comment", 'variables': [{'original_name': 'a1', 'new_name': 'example1'}, {'original_name': 'a2', 'new_name': 'example2'}, {'original_name': 'a3', 'new_name': 'example3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}, {'original_name': 'v3', 'new_name': 'examplev3'}]}

class FunctionNameWidget(QWidget):
    accepted = True

    def __init__(self, function_name):
        super(FunctionNameWidget, self).__init__()
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft| QtCore.Qt.AlignVCenter)

        group_box = QtWidgets.QGroupBox("aiDAPal Function Name")
        group_layout = QtWidgets.QHBoxLayout()
        group_layout.setAlignment(QtCore.Qt.AlignLeft| QtCore.Qt.AlignVCenter)
        group_layout.setSpacing(10)

        checkbox = QtWidgets.QCheckBox()
        checkbox.setCheckState(QtCore.Qt.Checked)
        checkbox.stateChanged.connect(self.accepted_state_change)

        group_layout.addWidget(checkbox)
        group_layout.addWidget(QtWidgets.QLabel(function_name))

        group_box.setLayout(group_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)
    
    def accepted_state_change(self, state):
        print(f'Accepted: {state == QtCore.Qt.Checked}')
        self.accepted = (state == QtCore.Qt.Checked)

class CommentWidget(QWidget):
    accepted = True

    def __init__(self, comment):
        super(CommentWidget, self).__init__()
        layout = QtWidgets.QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft| QtCore.Qt.AlignVCenter)

        group_box = QtWidgets.QGroupBox("aiDAPal Comment")
        group_layout = QtWidgets.QHBoxLayout()
        group_layout.setAlignment(QtCore.Qt.AlignLeft| QtCore.Qt.AlignVCenter)
        group_layout.setSpacing(10)

        checkbox = QtWidgets.QCheckBox()
        checkbox.setCheckState(QtCore.Qt.Checked)
        checkbox.stateChanged.connect(self.accepted_state_change)

        comment_area = QtWidgets.QLabel(comment)
        comment_area.setWordWrap(True)
        comment_area.setMinimumWidth(500)
        
        group_layout.addWidget(checkbox)
        group_layout.addWidget(comment_area)
        group_box.setLayout(group_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)

    def accepted_state_change(self, state):
        print(f'Accepted: {state == QtCore.Qt.Checked}')
        self.accepted = (state == QtCore.Qt.Checked)

class VariableWidget(QWidget):
    accepted = True
    def __init__(self, variables):
        super(VariableWidget, self).__init__()
        layout = QtWidgets.QGridLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

        group_box = QtWidgets.QGroupBox("aiDAPal Variables")
        group_layout = QtWidgets.QGridLayout()
        group_layout.setAlignment(QtCore.Qt.AlignLeft| QtCore.Qt.AlignVCenter)
        group_layout.setSpacing(10)
        self.checkboxes = []
        columns = 3
        for i in range(len(variables)):
            row = i // columns
            col = i % columns * 3  # Multiply by 3 for checkbox, original_name, and new_name
            
            original_name = variables[i]['original_name']
            new_name = variables[i]['new_name']
            checkbox = QtWidgets.QCheckBox()
            checkbox.setCheckState(QtCore.Qt.Checked)
            checkbox.stateChanged.connect(self.accepted_state_change)
            self.checkboxes.append(checkbox)

            frame = QtWidgets.QFrame()
            frame.setFrameStyle(QtWidgets.QFrame.Panel | QtWidgets.QFrame.Raised)
            frame_layout = QtWidgets.QHBoxLayout()
            frame_layout.addWidget(checkbox)
            frame_layout.addWidget(QtWidgets.QLabel(original_name))
            frame_layout.addWidget(QtWidgets.QLabel(new_name))
            frame.setLayout(frame_layout)
            group_layout.addWidget(frame, row, col)


        group_box.setLayout(group_layout)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        scroll_area.setWidget(group_box)
        layout.addWidget(scroll_area)


        layout.addWidget(group_box)

        self.setLayout(layout)

    def accepted_state_change(self, state):
        print(f'Accepted: {state == QtCore.Qt.Checked}')
        self.accepted = (state == QtCore.Qt.Checked)
    
    def get_states(self):
        # Get the state of each checkbox
        return [checkbox.isChecked() for checkbox in self.checkboxes]

class aiDAPalUIForm(ida_kernwin.PluginForm):

    ida_pal_results = None
    current_func = None

    def __init__(self,ida_pal_results,current_func):
        super(aiDAPalUIForm, self).__init__()
        self.ida_pal_results = ida_pal_results
        self.current_func = current_func

    def OnCreate(self, form):
        """
        Called when the widget is created
        """
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        
        self.PopulateForm()
        #self.parent.setMinimumWidth(800)
        #self.parent.setFixedSize(self.parent.sizeHint())


    def PopulateForm(self):
        # Create layout
        layout1 = QtWidgets.QVBoxLayout()
        layout1.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        layout1.addWidget(FunctionNameWidget(self.ida_pal_results['function_name']))
        layout1.addWidget(CommentWidget(self.ida_pal_results['comment']))
        layout1.addWidget(VariableWidget(self.ida_pal_results['variables']))

        # Create buttons
        accept_button = QtWidgets.QPushButton("Accept")
        cancel_button = QtWidgets.QPushButton("Cancel")

        layout1.addStretch()

        # Connect buttons to functions
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button.clicked.connect(self.on_cancel_clicked)
        layout1.addWidget(accept_button)
        layout1.addWidget(cancel_button)
        self.parent.setLayout(layout1)

    def get_variable_states(self):
        # List to hold the state values
        state_values = []

        # Iterate over the widgets in the layout
        for i in range(self.parent.layout().count()):
            widget = self.parent.layout().itemAt(i).widget()

            # Check if the widget is an instance of VariableWidget
            if isinstance(widget, VariableWidget):
                state_values.extend(widget.get_states())
        return state_values

    def get_comment_state(self):
        # Get the comment widget
        for i in range(self.parent.layout().count()):
            widget = self.parent.layout().itemAt(i).widget()
            if isinstance(widget, CommentWidget):
                return widget.accepted
    
    def get_function_name_state(self):
        # Get the function name widget
        for i in range(self.parent.layout().count()):
            widget = self.parent.layout().itemAt(i).widget()
            if isinstance(widget, FunctionNameWidget):
                return widget.accepted

    def on_accept_clicked(self):
        # Handle OK button click
        vstates = self.get_variable_states()
        for v in range(len(self.ida_pal_results['variables'])):
            self.ida_pal_results["variables"][v]["accepted"] = vstates[v]
            if vstates[v]:
                print(f'{self.ida_pal_results["variables"][v]["original_name"]} -> {self.ida_pal_results["variables"][v]["new_name"]}: Accepted')
        
        if not self.get_comment_state():
            self.ida_pal_results["comment"] = None
        if not self.get_function_name_state():
            self.ida_pal_results["function_name"] = None

        print(self.ida_pal_results)
        self.do_update()

    def do_update(self):
        new_cmt = ''
        new_name = None
        if self.ida_pal_results["comment"]:
            # split the comment into lines of 80 characters max
            new_cmt = '\n'.join(textwrap.wrap(self.ida_pal_results['comment'], width=80))
            if self.current_func:
                cf = ida_funcs.get_func(self.current_func.entry_ea)
                ida_funcs.set_func_cmt(cf,new_cmt,False)
        
        if self.ida_pal_results["function_name"]:
            new_name = f"{self.ida_pal_results['function_name']}_{hex(self.current_func.entry_ea)[2:]}"
            print(f'Trying function name update {new_name}')
            if ida_name.set_name(self.current_func.entry_ea,new_name,ida_name.SN_CHECK):
                print('successfully updated name')

        for var in self.ida_pal_results['variables']:
            if var['accepted']:
                print(f"trying function var - {var['original_name']} - {var['new_name']}")
                if ida_hexrays.rename_lvar(self.current_func.entry_ea,var['original_name'],var['new_name']):
                    print(f"Updated function var - {var['original_name']} - {var['new_name']}")
        
        self.current_func.refresh_func_ctext()
        self.Close(0)


    def on_cancel_clicked(self):
        self.Close(0)

    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        pass

class aiDAPalUI:
    def __init__(self, ida_pal_results=None,cur_func=None):
        if ida_pal_results is None:
            self.ida_pal_results = example_input
        else:
            self.ida_pal_results = ida_pal_results
            self.plg = aiDAPalUIForm(self.ida_pal_results,cur_func)
            self.plg.Show("aiDAPal Results")



