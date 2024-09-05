from burp import IBurpExtender, IHttpListener
import json

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Modify JSON Response")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response:
                response_info = self.helpers.analyzeResponse(response)
                body_offset = response_info.getBodyOffset()
                body_bytes = response[body_offset:]
                body_str = self.helpers.bytesToString(body_bytes)

                # Check if the response contains the JSON structure you're looking for
                if '{"Permitted":null,' in body_str:
                    try:
                        json_data = json.loads(body_str)

                        # Move Denied permissions to Permitted
                        json_data['Permitted'] = json_data.get('Denied', [])
                        json_data['Denied'] = None  # Set Denied to null

                        # Convert back to string
                        modified_body = json.dumps(json_data)

                        # Rebuild the response with the modified body
                        new_response = self.helpers.buildHttpMessage(response_info.getHeaders(), modified_body)
                        messageInfo.setResponse(new_response)

                    except Exception as e:
                        print("Error modifying response: %s" % str(e))  # Using older string formatting
