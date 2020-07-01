import org.parosproxy.paros.network.HttpMessage
import org.apache.commons.httpclient.URI
import org.jsoup.Jsoup
import org.jsoup.nodes.Element
import java.util.Optional
import org.parosproxy.paros.network.HttpSender
import org.parosproxy.paros.control.Control
import org.zaproxy.zap.extension.alert.ExtensionAlert
import org.parosproxy.paros.core.scanner.Alert
import org.parosproxy.paros.model.HistoryReference
import org.parosproxy.paros.model.Model
import org.parosproxy.paros.view.View
import org.parosproxy.paros.extension.history.ExtensionHistory


void invokeWith(HttpMessage msg) {
	sender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 6)
	URI origin = msg.getRequestHeader().getURI()
	msg = msg.cloneRequest()
	msg.getRequestHeader().setMethod("GET")

	// NO LAYOUT CHECK
	reqUri = new URI(origin.getScheme(), origin.getAuthority(), "/sitecore/service/nolayout.aspx", null, null)
	msg.getRequestHeader().setURI(reqUri)
	sender.sendAndReceive(msg,false)
	checkResponseByCSSQuery(msg, "title:contains(Layout Not Found)").ifPresent{evidence -> raiseAlert(50000,
															Alert.RISK_MEDIUM,
															Alert.CONFIDENCE_HIGH,
															"Information Discloseure - Sensitive Application Information",
															"The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
															"The repsonse appears to contain information which may help an attacker.",
															"Follow Sitecore Security Hardening Guide, see references",
															evidence,
															200,
															13,
															"https://doc.sitecore.com/SdnArchive/upload/sitecore7/75/sitecore_security_hardening_guide-sc75-usletter.pdf",
															msg) }
}





Optional<String> checkResponseByCSSQuery(final HttpMessage msg, final String cssQuery) {
	if (msg.getResponseHeader().isHtml()) {
		return Optional.ofNullable(msg.getResponseBody().toString())
								.map{ body -> Jsoup.parse(body, msg.getRequestHeader().getURI().toString()).select(cssQuery).first() }
								.filter{element -> element != null }
								.map{ element -> element.outerHtml() }
	}
	return Optional.empty()
}

void raiseAlert(int pluginId, int risk, int confidence, String alertName, String description, String otherInfo,
			 String solution, String evidence, int cweId, int wascId, String reference, HttpMessage msg) 
{
	extAlert = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.NAME)
	href = addToHistory(msg)
	alert = new Alert(pluginId, risk, confidence, alertName)
	alert.setDescription(description)
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
}


HistoryReference addToHistory(msg) {
	extHistory = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.NAME)
	if(extHistory) {
		historyRef = new HistoryReference(Model.getSingleton().getSession(), HistoryReference.TYPE_PROXIED, msg)
		historyRef.addTag("Sitecore")
		if (View.isInitialised()) {
			extHistory.addHistory(historyRef)
			Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg)
			return historyRef
		}
	}
}