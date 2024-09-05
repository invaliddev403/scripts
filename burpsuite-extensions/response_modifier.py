from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTable, JButton, JTextField, JLabel, JScrollPane, BoxLayout, JComboBox
from javax.swing.table import AbstractTableModel
from javax.swing import JOptionPane
import re
import java.util.regex.Pattern as Pattern
import java.lang.Boolean

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Response Modifier")
        self._callbacks.registerHttpListener(self)

        # GUI Components
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.url_field = JTextField(20)
        self.modify_field = JTextField(20)
        self.request_type_box = JComboBox(["GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "PATCH"])
        self.add_button = JButton("Add Rule", actionPerformed=self.add_rule)
        self.edit_button = JButton("Edit Selected Rule", actionPerformed=self.edit_rule)
        self.remove_button = JButton("Remove Selected Rule", actionPerformed=self.remove_rule)

        self.panel.add(JLabel("URL or URL Pattern:"))
        self.panel.add(self.url_field)
        self.panel.add(JLabel("Modification Text:"))
        self.panel.add(self.modify_field)
        self.panel.add(JLabel("Request Type:"))
        self.panel.add(self.request_type_box)

        # Panel for buttons
        button_panel = JPanel()
        button_panel.add(self.add_button)
        button_panel.add(self.edit_button)
        button_panel.add(self.remove_button)
        self.panel.add(button_panel)

        self.rules_table = RulesTableModel()
        self.table = JTable(self.rules_table)

        # Enable checkboxes in the first column
        self.table.getColumnModel().getColumn(0).setCellEditor(self.table.getDefaultEditor(java.lang.Boolean))
        self.table.getColumnModel().getColumn(0).setCellRenderer(self.table.getDefaultRenderer(java.lang.Boolean))

        scroll_pane = JScrollPane(self.table)
        self.panel.add(scroll_pane)

        self._callbacks.customizeUiComponent(self.panel)
        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Response Modifier"

    def getUiComponent(self):
        return self.panel

    def add_rule(self, event):
        url_input = self.url_field.getText().strip()
        modification = self.modify_field.getText().strip()
        request_type = self.request_type_box.getSelectedItem()
        if url_input and modification:
            if self.is_valid_url(url_input):
                self.rules_table.add_rule(request_type, "url", url_input, modification)
            else:
                self.rules_table.add_rule(request_type, "regex", Pattern.compile(url_input), modification)

    def edit_rule(self, event):
        selected_row = self.table.getSelectedRow()
        if selected_row != -1:  # Ensure a row is selected
            # Get current values from the selected row
            current_request_type = self.rules_table.getValueAt(selected_row, 1)
            current_rule_type = self.rules_table.getValueAt(selected_row, 2)
            current_pattern = self.rules_table.getValueAt(selected_row, 3)
            current_modification = self.rules_table.getValueAt(selected_row, 4)

            # Set the values in the input fields
            self.request_type_box.setSelectedItem(current_request_type)
            self.url_field.setText(str(current_pattern))
            self.modify_field.setText(current_modification)

            # When the user clicks "Add Rule" again, replace the current rule with the new values
            def update_rule(event):
                new_request_type = self.request_type_box.getSelectedItem()
                new_pattern = self.url_field.getText().strip()
                new_modification = self.modify_field.getText().strip()

                if new_pattern and new_modification:
                    if self.is_valid_url(new_pattern):
                        self.rules_table.update_rule(selected_row, new_request_type, "url", new_pattern, new_modification)
                    else:
                        self.rules_table.update_rule(selected_row, new_request_type, "regex", Pattern.compile(new_pattern), new_modification)
                    # Restore the original add_rule method
                    self.add_button.removeActionListener(self.add_button.actionListeners[0])
                    self.add_button.addActionListener(self.add_rule)
                    self.add_button.setText("Add Rule")

            # Temporarily override the Add Rule button to update the rule
            self.add_button.setText("Save Changes")
            self.add_button.removeActionListener(self.add_button.actionListeners[0])
            self.add_button.addActionListener(update_rule)

    def remove_rule(self, event):
        selected_row = self.table.getSelectedRow()
        if selected_row != -1:  # Ensure a row is actually selected
            self.rules_table.remove_rule(selected_row)

    def is_valid_url(self, url):
        return url.startswith("http://") or url.startswith("https://")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzed_response = self._helpers.analyzeResponse(response)
            body = response[analyzed_response.getBodyOffset():].tostring()

            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
            method = self._helpers.analyzeRequest(messageInfo).getMethod()

            # Remove :443 or :80 from the URL if present
            url = re.sub(r':443(?=/|$)', '', url)  # Remove :443 only if followed by a slash or end of string
            url = re.sub(r':80(?=/|$)', '', url)  # Remove :80 only if followed by a slash or end of string

            # Iterate over the rules and apply only if enabled
            for i in range(self.rules_table.getRowCount()):
                enabled = self.rules_table.getValueAt(i, 0)
                request_type = self.rules_table.getValueAt(i, 1)
                rule_type = self.rules_table.getValueAt(i, 2)
                pattern = self.rules_table.getValueAt(i, 3)
                modification = self.rules_table.getValueAt(i, 4)

                if enabled and method == request_type:
                    if rule_type == "url" and url == str(pattern):
                        # Match found for a direct URL match
                        if not body.strip():
                            body = modification
                        else:
                            body += modification

                        headers = analyzed_response.getHeaders()
                        new_headers = []
                        for header in headers:
                            if not header.lower().startswith("content-length"):
                                new_headers.append(header)
                        new_headers.append("Content-Length: {}".format(len(body)))

                        modified_response = self._helpers.buildHttpMessage(
                            new_headers,
                            body
                        )
                        messageInfo.setResponse(modified_response)
                        break
                    elif rule_type == "regex" and pattern.matcher(url).find():
                        # Match found for a regex pattern
                        if not body.strip():
                            body = modification
                        else:
                            body += modification

                        headers = analyzed_response.getHeaders()
                        new_headers = []
                        for header in headers:
                            if not header.lower().startswith("content-length"):
                                new_headers.append(header)
                        new_headers.append("Content-Length: {}".format(len(body)))

                        modified_response = self._helpers.buildHttpMessage(
                            new_headers,
                            body
                        )
                        messageInfo.setResponse(modified_response)
                        break


class RulesTableModel(AbstractTableModel):
    def __init__(self):
        self.column_names = ["Enabled", "Request Type", "Type", "Pattern", "Modification Text"]
        self.data = []

    def getColumnCount(self):
        return len(self.column_names)

    def getRowCount(self):
        return len(self.data)

    def getColumnName(self, col):
        return self.column_names[col]

    def getValueAt(self, row, col):
        return self.data[row][col]

    def isCellEditable(self, row, col):
        return col == 0  # Only the "Enabled" checkbox is editable

    def setValueAt(self, value, row, col):
        if col == 0:  # Only update the "Enabled" status
            self.data[row][col] = value
            self.fireTableCellUpdated(row, col)

    def add_rule(self, request_type, rule_type, pattern, modification):
        self.data.append([True, request_type, rule_type, pattern, modification])
        self.fireTableDataChanged()

    def update_rule(self, index, request_type, rule_type, pattern, modification):
        if 0 <= index < len(self.data):
            self.data[index] = [True, request_type, rule_type, pattern, modification]
            self.fireTableDataChanged()

    def remove_rule(self, index):
        if 0 <= index < len(self.data):
            del self.data[index]
            self.fireTableDataChanged()
