import org.parosproxy.paros.network.HttpMessage
import org.parosproxy.paros.model.Model
import org.parosproxy.paros.model.SiteMap
import org.parosproxy.paros.model.SiteNode
import org.parosproxy.paros.extension.history.ExtensionHistory
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

@Field final HttpSender sender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(), true, 6)

void invokeWith(HttpMessage msg){
	HttpMessage errorPage1 = getErrorPage(msg)
	HttpMessage startPage = getStartPage(msg)
	final int statusCode = errorPage1.getResponseHeader().getStatusCode()
	println(statusCode)
	if (statusCode == 404) {
		println("Filter based on status code 404")
		Predicate<SiteNode> statusCodeFilter = { node -> node.getHistoryReference() != null && node.getHistoryReference().getStatusCode() == statusCode }
		filterTree(msg, statusCodeFilter)
	}
	else if (statusCode >= 301 && statusCode <= 302) {
		String redirectLocation = errorPage1.getRequestHeader().getHeader("Location")
		// TODO handle redirect location
	}
	else if (statusCode == 200) {
		HttpMessage errorPage2 = getErrorPage(msg)
		String errorPageTitle2 = getTitle(errorPage2)
		String errorPageTitle1 = getTitle(errorPage1)
		String startPageTitle = getTitle(startPage)
		if (errorPageTitle1.equals(errorPageTitle2) && !startPageTitle.equals(errorPageTitle1)) {
			println("Error Page Title 1 " + errorPageTitle1)
			println("Error Page Title 2 " + errorPageTitle2)
			println("Start Page Title " + startPageTitle)
			println("Filter by title [" + errorPageTitle1 + "]")
			Predicate<SiteNode> titleFilter = { node -> 
												if (node.getHistoryReference() != null) {
													HttpMessage nodeMsg = node.getHistoryReference().getHttpMessage()
													return StringUtils.equals(getTitle(nodeMsg), errorPageTitle1)
												}
										return false
										}
			filterTree(msg, titleFilter)
		}
		else {
			String errorPageHash1 = DigestUtils.sha256Hex(errorPage1.getResponseBody().toString())
			String errorPageHash2 = DigestUtils.sha256Hex(errorPage2.getResponseBody().toString())
			if (errorPageHash1.equals(errorPageHash2)) {
				println("Error Page 1 Hash: " + errorPageHash1)
				println("Error Page 2 Hash: " + errorPageHash2)	
				println("Calculate Hashes on full error page")
				Predicate<SiteNode> hashFilter = { node -> 
												String responseBodyAsString = getBodyFromNode(node)
												if (responseBodyAsString != null) {
													return StringUtils.equals(DigestUtils.sha256Hex(responseBodyAsString).toString(), errorPageHash1)
												}
												return false
											}
				filterTree(msg, hashFilter)
			}
			else
			{
				println("Calculate hash depending on most common part")
				String[] splittedErrorPage1 = errorPage1.getResponseBody().toString().split("\n")
				String[] splittedErrorPage2 = errorPage2.getResponseBody().toString().split("\n")
				List<String> startEquals = new ArrayList<String>()
				List<String> endEquals = new ArrayList<String>()
				int length = Math.min(splittedErrorPage1.length, splittedErrorPage2.length)
				for (int i = 0; i < length; i++) {
					if (StringUtils.equals(splittedErrorPage1[i], splittedErrorPage2[i])) {
						startEquals.add(splittedErrorPage1[i])
					}
					else {
						break
					}
				}
				for (int j = 0; j < length; j++) {
					if (StringUtils.equals(splittedErrorPage1[splittedErrorPage1.length-(j + 1)], splittedErrorPage2[splittedErrorPage2.length-(j + 1)])) {
						endEquals.add(splittedErrorPage1[splittedErrorPage1.length-(j + 1)])
					}
					else {
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
				
				if (startEquals.size() >= endEquals.size())
				{
					Predicate<SiteNode> startPredicate = { node -> return StringUtils.equals(startHash, getStartHashFromBody(node,startEquals.size())) }
					filterTree(msg, startPredicate)
				}
				else {
					Predicate<SiteNode> endPredicate = { node -> return StringUtils.equals(endHash, getEndHashFromBody(node,endEquals.size())) }
					filterTree(msg, endPredicate)
				}
			}
		}
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
	if (predicate.test(node)) {
		println("Removing Node: " + node.getHierarchicNodeName())
		ExtensionHistory.purge(sitesTree, current)
		return false
	}
	return false
}

void filterTree(HttpMessage msg, Predicate<SiteNode> predicate) {
	SiteMap sitestree = Model.getSingleton().getSession().getSiteTree()
	SiteNode node = sitestree.findNode(msg, true)
	if (node != null) {
		removeDefaultErrorPage(sitestree, node, predicate)
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

HttpMessage getErrorPage(HttpMessage msg) {
	URI original = msg.getRequestHeader().getURI()
	return request(msg, String.format("%s%s/%s", StringUtils.endsWith(original.getPath(), "/") ? original.getPath() : original.getPath() + "/", UUID.randomUUID().toString(),UUID.randomUUID().toString()), false)
}

HttpMessage getStartPage(HttpMessage msg) {
	URI original = msg.getRequestHeader().getURI()
	return request(msg, "/", true)
}

String getTitle(HttpMessage msg){
	if (msg == null) return null
	Source source = new Source(msg.getResponseBody().toString())
	Element titleElement=source.getFirstElement(HTMLElementName.TITLE)
	if (titleElement==null) return null
	return CharacterReference.decodeCollapseWhiteSpace(titleElement.getContent())
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
