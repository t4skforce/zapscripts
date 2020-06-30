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
	// Copy requests before reusing them
	URI origin = msg.getRequestHeader().getURI()
	msg = msg.cloneRequest()
	// Inject your payload
	msg.getRequestHeader().setMethod("GET")
	reqUri = new URI(origin.getScheme(), origin.getAuthority(), "/sitecore/service/nolayout.aspx", null, null)
	msg.getRequestHeader().setURI(reqUri)
	sender.sendAndReceive(msg,false)
	// Test the response here, and make other requests as required
	validate(msg).ifPresent { evidence ->	extAlert = Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.NAME)
									href = addToHistory(msg)
									alert = new Alert(50000, Alert.RISK_MEDIUM,Alert.CONFIDENCE_HIGH, 'Information Discloseure - Sensitive Application Information')
									alert.setDescription('The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.')
									alert.setOtherInfo('The repsonse appears to contain information which may help an attacker.')
									alert.setSolution('Follow Sitecore Security Hardening Guide, see references')
									alert.setEvidence(evidence)
									alert.setCweId(200)
									alert.setWascId(13)
									alert.setReference('https://doc.sitecore.com/SdnArchive/upload/sitecore7/75/sitecore_security_hardening_guide-sc75-usletter.pdf')
									alert.setHistoryRef(href)
									alert.setMessage(msg)
									alert.setUri(msg.getRequestHeader().getURI().toString())
									extAlert.alertFound(alert,href)
						}
}

Optional<String> validate(HttpMessage msg) {
	// First check if the status code is valid
	if (msg.getResponseHeader().isText()) {
		return Optional.ofNullable(msg.getResponseBody().toString())
								.map{ body -> Jsoup.parse(body, msg.getRequestHeader().getURI().toString()).select('title:contains(Layout Not Found)').first() }
								.filter{element -> element != null }
								.map{ element -> element.outerHtml() }
	}
	return Optional.empty()
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