import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.model.Model
import org.parosproxy.paros.model.SiteMap
import org.parosproxy.paros.model.SiteNode
import org.apache.commons.lang3.ArrayUtils
import java.lang.*
import org.parosproxy.paros.network.HttpSender
import org.apache.commons.httpclient.URI
import java.util.UUID
import org.apache.commons.lang3.StringUtils
import groovy.transform.Field
import net.htmlparser.jericho.*
import org.apache.commons.codec.digest.DigestUtils
import java.util.function.Predicate
import org.parosproxy.paros.network.HttpHeader
import org.parosproxy.paros.core.scanner.Alert
import org.zaproxy.zap.extension.history.PopupMenuPurgeSites

@Field final int alertThreshold = Alert.RISK_MEDIUM
@Field final HttpSender sender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 6)

void invokeWith(HttpMessage msg){
	if (isValidStartPoint(msg)) {
		int originalMessageStatusCode = msg.getResponseHeader().getStatusCode()
		String originalResponseBody = msg.getResponseBody().toString()

		HttpMessage testMessage = msg.cloneRequest()
		sender.sendAndReceive(testMessage, false)

		int testMessageStatusCode = testMessage.getResponseHeader().getStatusCode()
		String testResponseBody = testMessage.getResponseBody().toString()

		List<Predicate<SiteNode>> predicates = new ArrayList()

		if (originalMessageStatusCode == testMessageStatusCode) {
			println()
			if (testMessage.getResponseHeader().isText()) {
				// Standard Predicates
				Predicate<SiteNode> nodeNotNullFilter = { node -> node != null }
				Predicate<SiteNode> historyReferenceFilter = { node -> node.getHistoryReference() != null }
				Predicate<SiteNode> statusCodeFilter = { node ->  node.getHistoryReference().getStatusCode() == testMessageStatusCode }
				Predicate<SiteNode> requestMethodFilter = { node -> StringUtils.equals(node.getHistoryReference().getMethod(), testMessage.getRequestHeader().getMethod())}
				Predicate<SiteNode> contentTypeFilter = { node -> StringUtils.equals(node.getHistoryReference().getHttpMessage().getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE), testMessage.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE))}
				Predicate<SiteNode> alertFilter = { node -> !node.getHistoryReference().getAlerts().stream().filter({ alert -> alert.getRisk() >= alertThreshold }).findFirst().isPresent()}
				
				predicates.add(nodeNotNullFilter)
				predicates.add(historyReferenceFilter)
				predicates.add(statusCodeFilter)
				predicates.add(requestMethodFilter)				
				predicates.add(contentTypeFilter)
				predicates.add(alertFilter)
				
				// Get hash from complete response body
				String originalMessageHash = DigestUtils.sha256Hex(msg.getResponseBody().toString())
				String testMessageHash = DigestUtils.sha256Hex(testMessage.getResponseBody().toString())
				if (StringUtils.equals(originalMessageHash, testMessageHash)) {
					// Create predicate to filter complete body hashes
					Predicate<SiteNode> hashFilter = 	{ node -> 	String responseBodyAsString = getBodyFromNode(node)
															if (responseBodyAsString != null) {
																return StringUtils.equals(DigestUtils.sha256Hex(responseBodyAsString).toString(), originalMessageHash)
															}
															return false
												}
					predicates.add(hashFilter)
				} else {
					// Create predicate from most commons parts
					String[] splittedOriginalPage = msg.getResponseBody().toString().split("\n")
					String[] splittedTestPage = testMessage.getResponseBody().toString().split("\n")
					List<String> startEquals = new ArrayList<String>()
					List<String> endEquals = new ArrayList<String>()
					int length = Math.min(splittedOriginalPage.length, splittedTestPage.length)
					for (int i = 0; i < length; i++) {
						if (StringUtils.equals(splittedOriginalPage[i], splittedTestPage[i])) {
							startEquals.add(splittedOriginalPage[i])
						} else {
							break
						}
					}
					for (int j = 0; j < length; j++) {
						if (StringUtils.equals(splittedOriginalPage[splittedOriginalPage.length-(j + 1)], splittedTestPage[splittedTestPage.length-(j + 1)])) {
							endEquals.add(splittedOriginalPage[splittedOriginalPage.length-(j + 1)])
						} else {
							break
						}
					}
					String startHash = DigestUtils.sha256Hex(StringUtils.join(startEquals, "\n"))
					Collections.reverse(endEquals)
					String endHash = DigestUtils.sha256Hex(StringUtils.join(endEquals, "\n"))
					println("Start Equals: " + startEquals.size())
					println("End Equals: " + endEquals.size())
					println("Start Hash " + startHash)
					println("End Hash " + endHash)
				
					if (startEquals.size() >= endEquals.size()) {
						Predicate<SiteNode> startPredicate = { node -> return StringUtils.equals(startHash, getStartHashFromBody(node,startEquals.size())) }
						predicates.add(startPredicate)
					} else {
						Predicate<SiteNode> endPredicate = { node -> return StringUtils.equals(endHash, getEndHashFromBody(node,endEquals.size())) }
						predicates.add(endPredicate)
					}
				}
				
			}
			else if (testMessage.getResponseHeader().isEmpty()) {
				String redirectLocation = errorPage1.getRequestHeader().getHeader("Location")
			}
		} else {
			println("Status Code mismatch original[" + originalMessageStatusCode + "] tested [" + testMessageStatusCode + "]")
		}

		Predicate<SiteNode> filterPredicate = { node -> return !predicates.stream().filter({ predicate -> return predicate.test(node) == false}).findFirst().isPresent()}
		filterTree(msg, filterPredicate)

	}
	else {
		println("Please select a valid page to filter!")
	}
	println("Done")
}

boolean removeDefaultErrorPage(SiteMap sitesTree, SiteNode node, Predicate<SiteNode> predicate) {
	int i;
	for (i=0; i < node.getChildCount();i++) {
		if (removeDefaultErrorPage(sitesTree, node.getChildAt(i), predicate)) {
			i--
		}
	}
	if (node.getChildCount() == 0 && predicate.test(node)) {
		println("Removing Node: " + node.getHierarchicNodeName())
		PopupMenuPurgeSites.purge(sitesTree, node)
		return true
	}
	return false
}

void filterTree(HttpMessage msg, Predicate<SiteNode> predicate) {
	SiteMap sitestree = Model.getSingleton().getSession().getSiteTree()
	SiteNode rootNode = getRootNode(msg)
	if (rootNode != null) {
		removeDefaultErrorPage(sitestree, rootNode, predicate)
	}
}

HttpMessage request(HttpMessage origin, String path, boolean followRedirect) {
	HttpMessage clone = origin.cloneRequest()
	URI originRequestURI = origin.getRequestHeader().getURI()
	URI reqURI = new URI(originRequestURI.getScheme(), originRequestURI.getAuthority(), path, null, null)
	clone.getRequestHeader().setURI(reqURI)
	println(reqURI.toString())
	sender.sendAndReceive(clone, followRedirect)
	return clone
}

String getBodyFromNode(SiteNode node) {
	if (node.getHistoryReference() != null) {
		HttpMessage nodeMsg = node.getHistoryReference().getHttpMessage()
		if (nodeMsg != null) {
			return nodeMsg.getResponseBody().toString()
		}
	}
	return null
}

String getStartHashFromBody(SiteNode node, int lineCount) {
	List<String> lines = new ArrayList<String>()
	String body = getBodyFromNode(node)
	if (body != null) {
		String[] splittedBody = body.split("\n")
		if (splittedBody.length >= lineCount) {
			for(int i = 0; i < lineCount; i++) {
				lines.add(splittedBody[i])
			}
			return DigestUtils.sha256Hex(StringUtils.join(lines, "\n")).toString()
		}
	}
	return null
}

String getEndHashFromBody(SiteNode node, int lineCount) {
	List<String> lines = new ArrayList<String>()
	String body = getBodyFromNode(node)
	if (body != null) {
		String[] splittedBody = body.split("\n")
		if (splittedBody.length >= lineCount) {
			for(int i = 0; i < lineCount; i++) {
				lines.add(splittedBody[splittedBody.length - (i + 1)])
			}
			Collections.reverse(lines)
			return DigestUtils.sha256Hex(StringUtils.join(lines, "\n")).toString()
		}
	}
	return null
}

boolean isValidStartPoint(HttpMessage msg) {
	int statusCode = msg.getResponseHeader().getStatusCode()
	return  statusCode != 0 && (!msg.getRequestHeader().isEmpty() || statusCode == 301 || statusCode == 302)
}

SiteNode getRootNode(HttpMessage msg) {
	SiteMap sitestree = Model.getSingleton().getSession().getSiteTree()
	SiteNode currentNode = sitestree.findNode(msg, false)
	println(currentNode)
	return getRootSiteNode(currentNode)
}

SiteNode getRootSiteNode(SiteNode node){
	if (node.getParent() != null && node.getParent().getParent() != null) {
		return getRootSiteNode(node.getParent())
	}
	return node
}
