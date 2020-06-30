"""
Targeted scripts can only be invoked by you, the user, eg via a right-click option on the Sites or History tabs
"""

from org.parosproxy.paros.network import HttpSender
from org.parosproxy.paros.model import Model
from org.parosproxy.paros.extension.history import ExtensionHistory
from org.parosproxy.paros.control import Control
from org.parosproxy.paros.model import HistoryReference
from org.parosproxy.paros.view import View
from java.awt import EventQueue
from org.apache.commons.httpclient import URI
from org.zaproxy.zap.extension.alert import ExtensionAlert
from org.parosproxy.paros.core.scanner import Alert

paths = ["/App_Config","/App_Config/ConnectionStrings.config","/sitecore/","/sitecore/admin","/sitecore/admin/login.aspx","/sitecore/debug","/sitecore/default.aspx","/sitecore/login","/sitecore/login.aspx","/sitecore/login/default.aspx","/sitecore/shell/WebService","/sitecore/shell/webservice/service.asmx","/sitecore/shell/webservice/service2.asmx","/sitecore/shell/sitecore.version.xml","/sitecore/service"]

def addToHistory(msg):
	extHistory = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME)
	if extHistory:
		historyRef = HistoryReference(Model.getSingleton().getSession(), HistoryReference.TYPE_PROXIED, msg);
		historyRef.addTag("Sitecore")
		if View.isInitialised():
			extHistory.addHistory(historyRef);
			Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg);
			return historyRef

# risk: 0: info, 1: low, 2: medium, 3: high 
# reliability: 0: falsePassitive, 1: suspicious, 2: warning
def raiseAlert(msg, risk=0, confidence=0, name="", description="", param=None, attack="", otherInfo="", solution="", evidence="", reference="", cweId=-1, wascId=-1):
	extAlert = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.NAME)
	if extAlert and msg:
		href = addToHistory(msg)
		alert = Alert(1337,risk,confidence,name)
		alert.setDescription(description)
		alert.setParam(param)
		alert.setAttack(attack)
		alert.setOtherInfo(otherInfo)
		alert.setSolution(solution)
		alert.setEvidence(evidence)
		alert.setCweId(cweId)
		alert.setWascId(wascId)
		alert.setReference(reference)
		alert.setHistoryRef(href)
		alert.setMessage(msg)
		alert.setUri(msg.getRequestHeader().getURI().toString())
		extAlert.alertFound(alert,href)


def invokeWith(msg):
	sender = HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), True, 6)
	uri = msg.getRequestHeader().getURI()
	
	for path in paths:
		reqUri = URI(uri.getScheme(),uri.getAuthority(),path,None,None)
		req = msg.cloneRequest()
		req.getRequestHeader().setURI(reqUri)
		sender.sendAndReceive(req,False)
		statusCode = req.getResponseHeader().getStatusCode()
		if statusCode in [200, 401, 403, 500]:
			raiseAlert(req, 3, 2, 'Sitecore default Page exposure', path+' should not be anonymously reachable. Allows for Information Disclosure.', solution="Follow Sitecore Security Hardening Guide, see references", evidence=req.getResponseHeader().getPrimeHeader(), reference="https://doc.sitecore.com/SdnArchive/upload/sitecore7/75/sitecore_security_hardening_guide-sc75-usletter.pdf")
			addToHistory(req)
		print(str(statusCode)+" - "+path)
