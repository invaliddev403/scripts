from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JLabel, JTextField, JButton, JCheckBox, JTextArea, JScrollPane, GroupLayout
import json

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Modify JSON Response")
        callbacks.registerHttpListener(self)

        # Create a custom tab in the UI
        self.panel = JPanel()
        self.createUI()
        callbacks.addSuiteTab(self)
    
    # ITab implementation to set the name and component of the tab
    def getTabCaption(self):
        return "Modify JSON"

    def getUiComponent(self):
        return self.panel

    def createUI(self):
        # Labels and input fields for key and values
        label_key1 = JLabel("Key 1 (to be replaced):")
        self.input_key1 = JTextField(20)
        self.input_key1.setText('Permitted')  # Default key for replacement
        
        label_key2 = JLabel("Key 2 (to copy from):")
        self.input_key2 = JTextField(20)
        self.input_key2.setText('Denied')  # Default key for replacement

        # Checkbox to enable copying key2's value to key1
        self.copy_checkbox = JCheckBox("Copy Key 2's Value to Key 1")
        self.copy_checkbox.setSelected(True)  # Default selected
        
        # Checkbox to apply to all URLs
        self.all_urls_checkbox = JCheckBox("Apply to All URLs")
        self.all_urls_checkbox.setSelected(True)  # Default is to apply to all URLs
        
        # Text area for entering specific URLs (in-scope items)
        label_url_list = JLabel("In-scope URLs (one per line):")
        self.url_list_area = JTextArea(5, 20)
        scroll_pane = JScrollPane(self.url_list_area)

        # Apply button
        apply_button = JButton('Apply', actionPerformed=self.update_values)

        # Layout
        layout = GroupLayout(self.panel)
        self.panel.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(label_key1)
                    .addComponent(label_key2)
                    .addComponent(self.copy_checkbox)
                    .addComponent(self.all_urls_checkbox)
                    .addComponent(label_url_list)
                    .addComponent(scroll_pane))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.input_key1)
                    .addComponent(self.input_key2)
                    .addComponent(apply_button))
        )

        layout.setVerticalGroup(
            layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(label_key1)
                    .addComponent(self.input_key1))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(label_key2)
                    .addComponent(self.input_key2))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.copy_checkbox))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self.all_urls_checkbox))
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(label_url_list))
                .addComponent(scroll_pane)
                .addComponent(apply_button)
        )

        # Disable value input fields (ignored)
        self.input_key1.setEnabled(True)  # We still allow editing of the key names
        self.input_key2.setEnabled(True)  # We still allow editing of the key names

        # Initialize the dynamic key variables and URL list
        self.key1 = None
        self.key2 = None
        self.copy_key2_to_key1 = False
        self.apply_to_all_urls = False
        self.url_list = []

    # Update the stored keys, checkbox state, and URL list when the button is pressed
    def update_values(self, event):
        self.key1 = self.input_key1.getText()  # Key to be replaced
        self.key2 = self.input_key2.getText()  # Key to copy from
        self.copy_key2_to_key1 = self.copy_checkbox.isSelected()
        self.apply_to_all_urls = self.all_urls_checkbox.isSelected()
        
        # Get the list of in-scope URLs from the text area
        self.url_list = [url.strip() for url in self.url_list_area.getText().splitlines() if url.strip()]
        
        print("Updated keys: %s will be replaced with %s" % (self.key1, self.key2))
        print("Copy Key 2 to Key 1: %s" % self.copy_key2_to_key1)
        print("Apply to All URLs: %s" % self.apply_to_all_urls)
        print("In-scope URLs: %s" % self.url_list)
    
    # This method handles HTTP responses
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            # Get the current URL
            url = self.helpers.analyzeRequest(messageInfo).getUrl().toString()

            # Check if we should apply to this URL
            if self.apply_to_all_urls or self.is_url_in_scope(url):
                response = messageInfo.getResponse()
                if response:
                    response_info = self.helpers.analyzeResponse(response)
                    body_offset = response_info.getBodyOffset()
                    body_bytes = response[body_offset:]
                    body_str = self.helpers.bytesToString(body_bytes)

                    try:
                        json_data = json.loads(body_str)

                        # If the checkbox is selected, copy key2's value to key1 dynamically from the response
                        if self.copy_key2_to_key1:
                            # Check if both key1 and key2 exist in the response body
                            if self.key2 in json_data and self.key1 in json_data:
                                # Replace key1's value with key2's value
                                json_data[self.key1] = json_data[self.key2]
                                print("Copying value from Key 2 (%s) to Key 1 (%s)" % (self.key2, self.key1))
                            else:
                                print("Error: One or both keys do not exist in the JSON response")

                        # Convert back to string
                        modified_body = json.dumps(json_data)

                        # Rebuild the response with the modified body
                        new_response = self.helpers.buildHttpMessage(response_info.getHeaders(), modified_body)
                        messageInfo.setResponse(new_response)

                    except Exception as e:
                        print("Error modifying response: %s" % str(e))

    # Function to check if the URL is in the list of in-scope URLs
    def is_url_in_scope(self, url):
        for in_scope_url in self.url_list:
            if in_scope_url in url:
                return True
        return False
