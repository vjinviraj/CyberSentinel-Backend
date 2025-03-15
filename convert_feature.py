import json

def extract_features_from_data(data):
    """
    Extract features from the provided data and assign scores based on the criteria.
    Handle missing or null values appropriately.
    """
    features = {}
    
    # UsingIP
    if "UsingIP" in data and "Using_ip" in data["UsingIP"]:
        features["UsingIP"] = -1 if data["UsingIP"]["Using_ip"] else 1
    else:
        # Default to legitimate if we can't determine
        features["UsingIP"] = 1
    
    # LongURL
    if "LongURL" in data and "url_length" in data["LongURL"]:
        url_length = data["LongURL"]["url_length"]
        if url_length > 75:
            features["LongURL"] = -1
        elif 54 <= url_length <= 75:
            features["LongURL"] = 0
        else:
            features["LongURL"] = 1
    else:
        # Default to medium risk if we can't determine
        features["LongURL"] = 0
    
    # ShortURL
    if "LongURL" in data and "is_short_url" in data["LongURL"]:
        features["ShortURL"] = -1 if data["LongURL"]["is_short_url"] else 1
    else:
        # Default to legitimate if not a known shortener
        features["ShortURL"] = 1
    
    # Symbol@
    if "Symbol@" in data and "has_@_symbol" in data["Symbol@"]:
        features["Symbol@"] = -1 if data["Symbol@"]["has_@_symbol"] else 1
    else:
        # Default to legitimate if we can't check
        features["Symbol@"] = 1
    
    # Redirecting//
    if "Redirecting//" in data and "has_double_slash_in_path" in data["Redirecting//"]:
        features["Redirecting//"] = -1 if data["Redirecting//"]["has_double_slash_in_path"] else 1
    else:
        # Default to legitimate if we can't check
        features["Redirecting//"] = 1
    
    # PrefixSuffix-
    if "PrefixSuffix-" in data and "hyphen_count" in data["PrefixSuffix-"]:
        features["PrefixSuffix-"] = -1 if data["PrefixSuffix-"]["hyphen_count"] > 0 else 1
    else:
        # Default to legitimate if we can't check
        features["PrefixSuffix-"] = 1
    
    # SubDomains
    if "SubDomains" in data and "subdomain_count" in data["SubDomains"]:
        subdomain_count = data["SubDomains"]["subdomain_count"]
        if subdomain_count >= 4:
            features["SubDomains"] = -1
        elif 2 <= subdomain_count <= 3:
            features["SubDomains"] = 0
        else:
            features["SubDomains"] = 1
    else:
        # Default to medium risk if we can't determine
        features["SubDomains"] = 0
    
    # HTTPS
    if "HTTPS" in data:
        is_https = data["HTTPS"].get("is_https", False)
        certificate = data["HTTPS"].get("certificate", {})
        
        if not is_https:
            features["HTTPS"] = -1
        elif is_https and certificate:
            # Check for valid certificate
            valid_until = certificate.get("valid_until", "")
            if valid_until:
                # Certificate exists and has expiration date - consider valid
                features["HTTPS"] = 1
            else:
                # Certificate info incomplete - medium risk
                features["HTTPS"] = 0
        else:
            # HTTPS but certificate info missing
            features["HTTPS"] = 0
    else:
        # Can't determine HTTPS status - medium risk
        features["HTTPS"] = 0
    
    # DomainRegLen
    if "AgeofDomain" in data and "age_days" in data["AgeofDomain"]:
        domain_age_days = data["AgeofDomain"]["age_days"]
        if domain_age_days < 365:  # less than 1 year
            features["DomainRegLen"] = -1
        elif 365 <= domain_age_days <= (3 * 365):  # 1-3 years
            features["DomainRegLen"] = 0
        else:  # more than 3 years
            features["DomainRegLen"] = 1
    else:
        # Can't determine domain age - suspicious
        features["DomainRegLen"] = -1
    
    # Favicon
    if "Favicon" in data and "favicon_domain_mismatch" in data["Favicon"]:
        features["Favicon"] = -1 if data["Favicon"]["favicon_domain_mismatch"] else 1
    elif "Favicon" in data and "favicon_found" in data["Favicon"]:
        # Favicon exists but no mismatch info - assume legitimate
        features["Favicon"] = 1
    else:
        # No favicon info - medium risk
        features["Favicon"] = 0
    
    # NonStdPort
    # Check if URL contains non-standard ports
    features["NonStdPort"] = 1  # Default to legitimate
    
    # HTTPSDomainURL
    if "HTTPS" in data and data["HTTPS"].get("is_https", False):
        # HTTPS present - legitimate
        features["HTTPSDomainURL"] = 1
    else:
        # No HTTPS or can't determine - medium risk
        features["HTTPSDomainURL"] = 0
    
    # RequestURL
    if "AnchorURL" in data:
        external_resources = data["AnchorURL"].get("external_links", 0)
        total_resources = data["AnchorURL"].get("anchors_count", 0)
        
        if total_resources > 0:
            external_percentage = (external_resources / total_resources) * 100
            if external_percentage > 50:
                features["RequestURL"] = -1
            elif 20 <= external_percentage <= 50:
                features["RequestURL"] = 0
            else:
                features["RequestURL"] = 1
        else:
            # No resources - legitimate
            features["RequestURL"] = 1
    else:
        # No resource info - medium risk
        features["RequestURL"] = 0
    
    # AnchorURL
    if "AnchorURL" in data:
        external_links = data["AnchorURL"].get("external_links", 0)
        total_links = data["AnchorURL"].get("anchors_count", 0)
        
        if total_links > 0:
            external_percentage = (external_links / total_links) * 100
            if external_percentage > 50:
                features["AnchorURL"] = -1
            elif 20 <= external_percentage <= 50:
                features["AnchorURL"] = 0
            else:
                features["AnchorURL"] = 1
        else:
            # No links - legitimate
            features["AnchorURL"] = 1
    else:
        # No anchor info - medium risk
        features["AnchorURL"] = 0
    
    # LinksInScriptTags
    if "LinksInScriptTags" in data:
        script_tags = data["LinksInScriptTags"].get("script_tags_count", 0)
        external_scripts = data["LinksInScriptTags"].get("external_scripts", 0)
        
        if script_tags > 0:
            external_percentage = (external_scripts / script_tags) * 100
            if external_percentage > 50:
                features["LinksInScriptTags"] = -1
            elif 20 <= external_percentage <= 50:
                features["LinksInScriptTags"] = 0
            else:
                features["LinksInScriptTags"] = 1
        else:
            # No script tags - legitimate
            features["LinksInScriptTags"] = 1
    else:
        # No script tags info - medium risk
        features["LinksInScriptTags"] = 0
    
    # ServerFormHandler
    if "ServerFormHandler" in data:
        external_form_handlers = data["ServerFormHandler"].get("external_form_handlers", 0)
        features["ServerFormHandler"] = -1 if external_form_handlers > 0 else 1
    else:
        # No form handler info - medium risk
        features["ServerFormHandler"] = 0
    
    # InfoEmail
    if "InfoEmail" in data and "emails" in data["InfoEmail"]:
        has_email = len(data["InfoEmail"]["emails"]) > 0
        features["InfoEmail"] = -1 if has_email else 1
    else:
        # No email info - legitimate
        features["InfoEmail"] = 1
    
    # AbnormalURL
    if "AbnormalURL" in data and "is_abnormal" in data["AbnormalURL"]:
        features["AbnormalURL"] = -1 if data["AbnormalURL"]["is_abnormal"] else 1
    else:
        # No abnormal URL info - medium risk
        features["AbnormalURL"] = 0
    
    # WebsiteForwarding
    if "Redirecting//" in data and "redirect_count" in data["Redirecting//"]:
        redirect_count = data["Redirecting//"]["redirect_count"]
        if redirect_count > 4:
            features["WebsiteForwarding"] = -1
        elif 2 <= redirect_count <= 4:
            features["WebsiteForwarding"] = 0
        else:
            features["WebsiteForwarding"] = 1
    elif "WebsiteForwarding" in data and "has_redirection" in data["WebsiteForwarding"]:
        # Use WebsiteForwarding info if available
        has_redirection = data["WebsiteForwarding"]["has_redirection"]
        features["WebsiteForwarding"] = 0 if has_redirection else 1  # Medium risk if redirecting
    else:
        # No redirection info - legitimate
        features["WebsiteForwarding"] = 1
    
    # StatusBarCust
    if "StatusBarCust" in data and "status_bar_manipulation" in data["StatusBarCust"]:
        features["StatusBarCust"] = -1 if data["StatusBarCust"]["status_bar_manipulation"] else 1
    else:
        # No status bar info - legitimate
        features["StatusBarCust"] = 1
    
    # DisableRightClick
    if "DisableRightClick" in data and "right_click_disabled" in data["DisableRightClick"]:
        features["DisableRightClick"] = -1 if data["DisableRightClick"]["right_click_disabled"] else 1
    else:
        # No right click info - legitimate
        features["DisableRightClick"] = 1
    
    # UsingPopupWindow
    if "UsingPopupWindow" in data and "uses_popups" in data["UsingPopupWindow"]:
        features["UsingPopupWindow"] = -1 if data["UsingPopupWindow"]["uses_popups"] else 1
    else:
        # No popup info - legitimate
        features["UsingPopupWindow"] = 1
    
    # IframeRedirection
    if "IframeRedirection" in data and "iframe_count" in data["IframeRedirection"]:
        iframe_count = data["IframeRedirection"]["iframe_count"]
        features["IframeRedirection"] = -1 if iframe_count > 0 else 1
    else:
        # No iframe info - legitimate
        features["IframeRedirection"] = 1
    
    # AgeofDomain
    if "AgeofDomain" in data and "age_days" in data["AgeofDomain"]:
        age_months = data["AgeofDomain"]["age_days"] / 30
        if age_months < 6:
            features["AgeofDomain"] = -1
        elif 6 <= age_months <= 12:
            features["AgeofDomain"] = 0
        else:
            features["AgeofDomain"] = 1
    else:
        # No domain age info - suspicious
        features["AgeofDomain"] = -1
    
    # DNSRecording
    if "DNSRecording" in data and "dns_available" in data["DNSRecording"]:
        features["DNSRecording"] = 1 if data["DNSRecording"]["dns_available"] else -1
    else:
        # No DNS info - suspicious
        features["DNSRecording"] = -1
    
    # WebsiteTraffic
    # This requires external APIs - default based on domain info
    if "AgeofDomain" in data and data["AgeofDomain"].get("age_days", 0) > 365:
        # If domain is older, assume moderate traffic
        features["WebsiteTraffic"] = 0
    else:
        # New domain, assume low traffic
        features["WebsiteTraffic"] = -1
    
    # PageRank
    # This requires external APIs - default based on domain info
    if "AgeofDomain" in data and data["AgeofDomain"].get("age_days", 0) > 730:  # 2 years
        # If domain is older, assume decent PageRank
        features["PageRank"] = 0
    else:
        # New domain, assume low PageRank
        features["PageRank"] = -1
    
    # GoogleIndex
    # This requires external APIs - default based on domain info
    if "AgeofDomain" in data and data["AgeofDomain"].get("age_days", 0) > 180:  # 6 months
        # If domain is not very new, assume it's indexed
        features["GoogleIndex"] = 1
    else:
        # Very new domain, assume not indexed
        features["GoogleIndex"] = -1
    
    # LinksPointingToPage
    # This requires external APIs - default based on domain info
    if "AgeofDomain" in data and data["AgeofDomain"].get("age_days", 0) > 365:
        # If domain is older, assume some backlinks
        features["LinksPointingToPage"] = 0
    else:
        # New domain, assume few/no backlinks
        features["LinksPointingToPage"] = -1
    
    # StatsReport
    # Default to legitimate if no reports specified
    features["StatsReport"] = 1
    
    return features

def main():
    try:
        # Load the JSON data from the provided file
        with open('analysis.json', 'r') as file:
            data = json.load(file)
        
        # Extract features
        features = extract_features_from_data(data)
        
        # Format the output as requested
        output = {"features": features}
        
        # Save the output to a JSON file
        with open('phishing_features.json', 'w') as outfile:
            json.dump(output, outfile,indent=2, sort_keys=True)
        
        print("Features extracted and saved to phishing_features.json")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()