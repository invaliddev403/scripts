from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JTable, JButton, JTextField, JLabel, JScrollPane, BoxLayout
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
        self.add_button = JButton("Add Rule", actionPerformed=self.add_rule)
        self.remove_button = JButton("Remove Selected Rule", actionPerformed=self.remove_rule)

        self.panel.add(JLabel("URL or URL Pattern:"))
        self.panel.add(self.url_field)
        self.panel.add(JLabel("Modification Text:"))
        self.panel.add(self.modify_field)
        self.panel.add(self.add_button)

        self.rules_table = RulesTableModel()
        self.table = JTable(self.rules_table)

        # Enable checkboxes in the first column
        self.table.getColumnModel().getColumn(0).setCellEditor(self.table.getDefaultEditor(java.lang.Boolean))
        self.table.getColumnModel().getColumn(0).setCellRenderer(self.table.getDefaultRenderer(java.lang.Boolean))

        scroll_pane = JScrollPane(self.table)
        self.panel.add(scroll_pane)
        self.panel.add(self.remove_button)  # Add the remove button below the table

        self._callbacks.customizeUiComponent(self.panel)
        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Response Modifier"

    def getUiComponent(self):
        return self.panel

    def add_rule(self, event):
        url_input = self.url_field.getText().strip()
        modification = self.modify_field.getText().strip()
        if url_input and modification:
            if self.is_valid_url(url_input):
                self.rules_table.add_rule("url", url_input, modification)
            else:
                self.rules_table.add_rule("regex", Pattern.compile(url_input), modification)

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
            
            # Remove :443 or :80 from the URL if present
            url = re.sub(r':443(?=/|$)', '', url)  # Remove :443 only if followed by a slash or end of string
            url = re.sub(r':80(?=/|$)', '', url)  # Remove :80 only if followed by a slash or end of string
        
            # Iterate over the rules and apply only if enabled
            for i in range(self.rules_table.getRowCount()):
                enabled = self.rules_table.getValueAt(i, 0)
                rule_type = self.rules_table.getValueAt(i, 1)
                pattern = self.rules_table.getValueAt(i, 2)
                modification = self.rules_table.getValueAt(i, 3)

                if "sfrank43" in url:
                    JOptionPane.showMessageDialog(None, "Results: " + "\n" + str(url).strip() + "\n" + str(pattern).strip())

                if enabled:
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
        self.column_names = ["Enabled", "Type", "Pattern", "Modification Text"]
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

    def add_rule(self, rule_type, pattern, modification):
        self.data.append([True, rule_type, pattern, modification])
        self.fireTableDataChanged()

    def remove_rule(self, index):
        if 0 <= index < len(self.data):
            del self.data[index]
            self.fireTableDataChanged()
