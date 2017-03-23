/*
 * Copyright (c) Members of the EGEE Collaboration. 2006-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors:
 * 2016-
 *    Mischa Salle <msalle@nikhef.nl>
 *    Rens Visser <rensv@nikhef.nl>
 *    NIKHEF Amsterdam, the Netherlands
 *    <grid-mw-security@nikhef.nl>
 */

package org.glite.authz.pep.pip.provider;

import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.util.LazyList;
import org.glite.authz.pep.pip.PIPProcessingException;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.CertificateUtils.Encoding;
import eu.emi.security.authn.x509.proxy.ProxyUtils;
import eu.emi.security.authn.x509.impl.OpensslNameUtils;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.PolicyInformation;

import org.bouncycastle.asn1.x509.Extension;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.List;
import java.security.cert.X509Certificate;

import static java.lang.String.format;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * This PIP can extract several different attributes from a X.509v3 certificate,
 * as obtained from the {@link ATTR_KEY_INFO} attribute, and stores them as
 * subject attributes. Which attributes are being set is determined by the
 * {@link #acceptedAttrIDs}. Note that the
 * <A href="https://twiki.cern.ch/twiki/bin/view/EMI/CommonXACMLProfileV1_1">EMI
 * Common XACML profile</A> differs from the
 * <A href="https://edms.cern.ch/document/1058175">EMI XACML Grid Worker Node
 * Authorization Profile</A> in the way the key-info is sent. This PIP can
 * handle both flavours.
 * @author Mischa Sall&eacute;, Rens Visser
 */
public class X509ExtractorPIP extends AbstractPolicyInformationPoint {
    /** Class logger instance. */
    private static final Logger LOG = LoggerFactory.getLogger(X509ExtractorPIP.class);

    /** Default name of key-info attribute(s) ({@value}) */
    private final static String ATTR_KEY_INFO = "urn:oasis:names:tc:xacml:1.0:subject:key-info";

    /** Default name of issuer DN attribute ({@value}) */
    protected final static String ATTR_X509_ISSUER = "http://authz-interop.org/xacml/subject/subject-x509-issuer";

    /** Default name of CA policy OIDs attribute ({@value}) */
    protected final static String ATTR_CA_POLICY_OID = "http://authz-interop.org/xacml/subject/ca-policy-oid";

    /** enum describing the different supported attributes to be set */
    protected enum AcceptedAttr {
	/** corresponds to {@link #ATTR_X509_ISSUER} */
	ACCEPT_ATTR_X509_ISSUER,
	/** corresponds to {@link #ATTR_CA_POLICY_OID} */
	ACCEPT_ATTR_CA_POLICY_OID,
    }

    /** Array of accepted attribute ID(s) in incoming request that will be
     * populated. Default none */
    private static AcceptedAttr[] acceptedAttrIDs = new AcceptedAttr[0];


    /**
     * Sets list of accepted attributes, default is empty
     * @param acceptedAttrIDs list of accepted attributes
     * @see AcceptedAttr
     */
    protected void setAcceptedAttrIDs(AcceptedAttr[] acceptedAttrIDs) {
	this.acceptedAttrIDs = acceptedAttrIDs;
    }

    /**
     * Constructs a X509ExtractorPIP instance, using both PIP ID and list of
     * accepted attributes
     * @param pipId ID of this PIP.
     * @param acceptedAttrIDs array of accepted attributes
     */
    public X509ExtractorPIP(String pipId, AcceptedAttr[] acceptedAttrIDs) {
	super(pipId);

	// Set list of accepted attributes
	if (acceptedAttrIDs!=null && acceptedAttrIDs.length > 0)
	    this.acceptedAttrIDs = acceptedAttrIDs;
    }

    /**
     * Constructs a X509ExtractorPIP instance, using only PIP ID, list of
     * accepted attributes needs to be set using
     * {@link #setAcceptedAttrIDs(AcceptedAttr[])}
     * @param pipId ID of this PIP.
     * @see #X509ExtractorPIP(String, AcceptedAttr[])
     * @see #setAcceptedAttrIDs(AcceptedAttr[])
     */
    public X509ExtractorPIP(String pipId) {
	this(pipId, null);
    }

    /**
     * {@inheritDoc}
     * This PIP adds {@value #ATTR_X509_ISSUER} and/or
     * {@value #ATTR_CA_POLICY_OID} attributes to the corresponding subjects.
     * @param request the incoming request.
     * @throws PIPProcessingException in case of errors.
     * @return boolean: true when attribute has been populated, false otherwise.
     */
    public boolean populateRequest(Request request) throws PIPProcessingException {
	long t0=System.nanoTime();
	boolean pipProcessed=false;

	// Do we need to do anything?
	if (acceptedAttrIDs==null || acceptedAttrIDs.length==0)	{
	    return false;
	}

	// Get all subjects from the request, should be at least one, warn when
	// there are more than 1
	Set<Subject> subjects = request.getSubjects();
	if (subjects.isEmpty())	{
	    LOG.error("Request has no subjects");
	    throw new PIPProcessingException("No subject found in request");
	}
	if (subjects.size()>1)	{
	    LOG.warn("Request has {} subjects, taking first match", subjects.size());
	}
	
	// Loop over all subjects to look for end-entity certificate
	for (Subject subject : subjects) {
	    if (subject==null)	{
		continue;
	    }
	    Set<Attribute> attributes = subject.getAttributes();
	    X509Certificate cert = getCertFromSubject(attributes);
	    if (cert == null)	{
		continue;
	    }

	    // Now see what we should handle
	    for (int i=0; i < acceptedAttrIDs.length; i++) {
		switch (acceptedAttrIDs[i])	{
		    case ACCEPT_ATTR_CA_POLICY_OID:
			String[] oids = getCAPolicyOids(cert);
			if (oids==null)	{ // no OIDs or error
			    LOG.debug("Certificate does not contain any OIDs");
			    break;
			}
			Attribute attrCAPolicyOids = new Attribute(ATTR_CA_POLICY_OID);
			Set<Object> values = attrCAPolicyOids.getValues();
			for (int j=0; j<oids.length; j++)   {
			    values.add(oids[j]);
			}
			attributes.add(attrCAPolicyOids);
			pipProcessed=true;
			// Log that we succeeded
			LOG.debug("Added attribute \"{}\" ({} value(s))", ATTR_CA_POLICY_OID, oids.length);
			break;
		    case ACCEPT_ATTR_X509_ISSUER:
			String str = cert.getIssuerX500Principal().getName();
			if (str==null)	{ // no OIDs or error
			    LOG.warn("Certificate does not contain a valid Issuer");
			    break;
			}
			String value = OpensslNameUtils.convertFromRfc2253(str, false);
			Attribute attrIssuerDN = new Attribute(ATTR_X509_ISSUER);
			attrIssuerDN.getValues().add(value);
			attributes.add(attrIssuerDN);
			pipProcessed=true;
			// Log that we succeeded
			LOG.debug("Added attribute \"{}\" ({})", ATTR_X509_ISSUER, value);
			break;
		    default:
			final String errorMsg = format("Unknown attribute %s specified", acceptedAttrIDs[i]);
			LOG.error(errorMsg);
			throw new PIPProcessingException(errorMsg);
		}
	    }
	}

	// Log statistics
	LOG.debug("PIP parsing took {} msec", (System.nanoTime()-t0)/1000000.0);

	return pipProcessed;
    }

    /**
     * Retrieves the end-entity certificate from a set of (subject)attributes.
     * Note that the EMI Common XACML Profile (see
     * https://twiki.cern.ch/twiki/bin/view/EMI/CommonXACMLProfileV1_1) sends a
     * possibly unordered list of base64 DER-encoded certs instead of a single
     * PEM-encoded certchain as done by the EMI WN profile
     * (https://edms.cern.ch/document/1058175/1.0.1)
     * @param attributes (subject) attributes to parse for EEC
     * @return end-entity certificate
     */
    private X509Certificate getCertFromSubject(Set<Attribute> attributes)	{
	// Protect against empty set
	if (attributes==null)	{
	    return null;
	}

	// Loop over all attributes, looking for ATTR_X509_ISSUER
	for (Attribute attr: attributes) {
	    if (attr==null) {
		continue;
	    }

	    if (ATTR_KEY_INFO.equals(attr.getId()))	{
		Set<Object> attributeValues = attr.getValues();
		if (attributeValues==null || attributeValues.size()==0)	{
		    LOG.warn("Skipping invalid key-info attr: value is empty");
		    continue;
		}

		// Inspect the first value
		String value = (String)attributeValues.iterator().next();
		if (value.startsWith("-----BEGIN "))	{
		    // assume WN profile: single PEM encoded chain. Should also
		    // be single-valued according to https://edms.cern.ch/document/1058175/1.0.1
		    if (attributeValues.size() > 1) {
			LOG.warn("key-info attr has >1 values, but is PEM, taking only first value.");
		    }
		} else {
		    // assume CommonXACMLProfile: base64 encoded blobs, might
		    // not be ordered, according to
		    // https://twiki.cern.ch/twiki/bin/view/EMI/CommonXACMLProfileV1_1
		    // so combine into PEM string ourselves and let canl-java
		    // loadCertificateChain() sort it for us.
		    StringBuilder pem = new StringBuilder();
		    for (Object attrval: attributeValues)    {
			pem.append("-----BEGIN CERTIFICATE-----\n");
			pem.append((String)attrval);
			pem.append("\n-----END CERTIFICATE-----\n");
		    }
		    value = pem.toString();
		}
		// Now convert PEM-string value to a X509Certificate
		InputStream pemReader = new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
		try {
		    // pemReader is closed by loadCertificateChain()
		    X509Certificate[] chain = CertificateUtils.loadCertificateChain(pemReader, Encoding.PEM);
		    return ProxyUtils.getEndUserCertificate(chain);
		} catch (Exception e) {
		    // This might be a IOException, but also for invalid base64
		    // a StringIndexOutOfBoundsException or a DecoderException
		    LOG.error("Skipping invalid key-info attr: Parsing value as a certificate failed: {}", e.getMessage());
		}
	    }
	}
	// No cert found
	LOG.info("No valid certificate found in set of attributes");
	return null;
    }

    /**
     * Tries to obtain policy OIDs from end-entity certificate
     * @param cert input (end-entity) certificate
     * @return String array of policy OIDs
     */
    private String[] getCAPolicyOids(X509Certificate cert)  {
	List<String> oidList = new LazyList<String>();

	// OID for certificate_policies (=2.5.29.32)
	String certPolicies = Extension.certificatePolicies.toString();

	// Grab bare extension value from certificate
	byte[] extvalue = cert.getExtensionValue(certPolicies);
	if (extvalue==null) {
	    return null;
	}

	// Try to parse the raw bytes as ASN1Sequence
	ASN1Sequence seq;
	try {
	    DEROctetString oct=(DEROctetString)(new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject());
	    seq = (ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(oct.getOctets())).readObject();
	} catch (IOException e)	{
	    LOG.error("Trying to obtain policyinfo from certificate failed: {}", e.getMessage());
	    return null;
	}

	// Parse the ASN1Sequence as policy information values
	for (int pos = 0; pos < seq.size(); pos++) {
	    PolicyInformation policyInfo = PolicyInformation.getInstance(seq.getObjectAt(pos));
	    oidList.add(policyInfo.getPolicyIdentifier().getId());
	}

	// Return oidList
	return oidList.toArray(new String[0]);
    }
}
