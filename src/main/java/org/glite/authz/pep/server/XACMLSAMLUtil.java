/*
 * Copyright 2008 EGEE Collaboration
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.glite.authz.pep.server;

import java.security.NoSuchAlgorithmException;

import org.glite.authz.common.util.Strings;
import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Subject;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.ctx.ActionType;
import org.opensaml.xacml.ctx.AttributeType;
import org.opensaml.xacml.ctx.AttributeValueType;
import org.opensaml.xacml.ctx.EnvironmentType;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResourceContentType;
import org.opensaml.xacml.ctx.ResourceType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.SubjectType;
import org.opensaml.xacml.profile.saml.XACMLAuthzDecisionQueryType;
import org.opensaml.xml.XMLObject;

/** XACML related helper functions. */
@SuppressWarnings("unchecked")
public final class XACMLSAMLUtil {

    /** Generator for message IDs. */
    private static IdentifierGenerator idGenerator;

    /** Builder of Action XMLObjects. */
    private static XACMLObjectBuilder<ActionType> actionBuilder;

    /** Builder of Attribute XMLObjects. */
    private static XACMLObjectBuilder<AttributeType> attributeBuilder;

    /** Builder of AttributeValue XMLObjects. */
    private static XACMLObjectBuilder<AttributeValueType> attributeValueBuilder;

    /** Builder of XACMLAuthzDecisionQuery XMLObjects. */
    private static SAMLObjectBuilder<XACMLAuthzDecisionQueryType> authzDecisionQueryBuilder;

    /** Builder of Body XMLObjects. */
    private static SOAPObjectBuilder<Body> bodyBuilder;

    /** Builder of Envelope XMLObjects. */
    private static SOAPObjectBuilder<Envelope> envelopeBuilder;

    /** Builder of Environment XMLObjects. */
    private static XACMLObjectBuilder<EnvironmentType> enviornmentBuilder;

    /** Builder of Issuer XMLObjects. */
    private static SAMLObjectBuilder<Issuer> issuerBuilder;

    /** Builder of Resource XMLObjects. */
    private static XACMLObjectBuilder<ResourceType> resourceBuilder;

    /** Builder of ResourceContent XMLObjects. */
    private static XACMLObjectBuilder<ResourceContentType> resourceContentBuilder;

    /** Builder of Request XMLObjects. */
    private static XACMLObjectBuilder<RequestType> requestBuilder;

    /** Builder of Subject XMLObjects. */
    private static XACMLObjectBuilder<SubjectType> subjectBuilder;

    /** Constructor. */
    private XACMLSAMLUtil() {
    }

    /**
     * Creates a SOAP message within which lies the XACML request.
     * 
     * @param bodyMessage the message that should be placed in the SOAP body
     * 
     * @return the generated SOAP envelope containing the message
     */
    public static Envelope buildSOAPRequest(XMLObject bodyMessage) {
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(bodyMessage);

        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);

        return envelope;
    }

    /**
     * Builds up the XACML-SAML AuthorizationDescisionQuery request around the given XACML request context.
     * 
     * @param xacmlRequestContext the XACML request context
     * @param issuerEntityId the entity ID of the message issuer
     * @param inputContextOnly true if the PDP should only consider the information within the request context, false if
     *            it may gather information from other places as well
     * @param returnContext true if the PDP should return the request context with the response
     * 
     * @return the constructed query
     */
    public static XACMLAuthzDecisionQueryType buildSAMLRequest(RequestType xacmlRequestContext, String issuerEntityId,
            boolean inputContextOnly, boolean returnContext) {
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(Issuer.ENTITY);
        issuer.setValue(issuerEntityId);

        XACMLAuthzDecisionQueryType samlRequest = authzDecisionQueryBuilder
                .buildObject(XACMLAuthzDecisionQueryType.DEFAULT_ELEMENT_NAME_XACML20,
                        XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);

        samlRequest.setID(idGenerator.generateIdentifier());
        samlRequest.setIssueInstant(new DateTime());
        samlRequest.setIssuer(issuer);
        samlRequest.setInputContextOnly(inputContextOnly);
        samlRequest.setReturnContext(returnContext);
        samlRequest.setRequest(xacmlRequestContext);
        return samlRequest;
    }

    /**
     * Converts a PEP simple-model request into a XACML request.
     * 
     * @param req PEP simple-model request
     * 
     * @return XACML request
     */
    public static RequestType toXACMLRequest(Request req) {
        RequestType request = requestBuilder.buildObject();

        request.setAction(toXACMLAction(req.getAction()));

        request.setEnvironment(toXACMLEnvironment(req.getEnvironment()));

        for (Resource res : req.getResources()) {
            request.getResources().add(toXACMLResource(res));
        }

        for (Subject subj : req.getSubjects()) {
            request.getSubjects().add(toXACMLSubject(subj));
        }

        return request;
    }

    /**
     * Converts a PEP simple-model subject in to a XACML request context subject.
     * 
     * @param subj PEP simple-model subject
     * 
     * @return XACML request context subject
     */
    public static SubjectType toXACMLSubject(Subject subj) {
        SubjectType subject = subjectBuilder.buildObject();
        subject.setSubjectCategory(subj.getCategory());

        for (Attribute attrib : subj.getAttributes()) {
            subject.getAttributes().add(toXACMLAttribute(attrib));
        }

        return subject;
    }

    /**
     * Converts a PEP simple-model resource in to a XACML request context resource.
     * 
     * @param res PEP simple-model resource
     * 
     * @return XACML request context resource
     */
    public static ResourceType toXACMLResource(Resource res) {
        ResourceType resource = resourceBuilder.buildObject();

        if (!Strings.isEmpty(res.getResourceContent())) {
            ResourceContentType resContent = resourceContentBuilder.buildObject();
            resContent.setValue(res.getResourceContent());
            resource.setResourceContent(resContent);
        }

        for (Attribute attrib : res.getAttributes()) {
            resource.getAttributes().add(toXACMLAttribute(attrib));
        }

        return resource;
    }

    /**
     * Converts a PEP simple-model action in to a XACML request context action.
     * 
     * @param act PEP simple-model action
     * 
     * @return XACML request context action
     */
    public static ActionType toXACMLAction(Action act) {
        ActionType action = actionBuilder.buildObject();
        for (Attribute attrib : act.getAttributes()) {
            action.getAttributes().add(toXACMLAttribute(attrib));
        }

        return action;
    }

    /**
     * Converts a PEP simple-model environment in to a XACML request context environment.
     * 
     * @param env PEP simple-model environment
     * 
     * @return XACML request context environment
     */
    public static EnvironmentType toXACMLEnvironment(Environment env) {
        EnvironmentType environment = enviornmentBuilder.buildObject();
        for (Attribute attrib : env.getAttributes()) {
            environment.getAttributes().add(toXACMLAttribute(attrib));
        }

        return environment;
    }

    /**
     * Converts a PEP simple-model attribute into a XACML request context attribute.
     * 
     * @param attrib PEP simple-model attribute
     * 
     * @return XACML request context attribute
     */
    public static AttributeType toXACMLAttribute(Attribute attrib) {
        AttributeType attribute = attributeBuilder.buildObject();
        attribute.setAttributeID(attrib.getId());
        attribute.setDataType(attrib.getDataType());
        attribute.setIssuer(attrib.getIssuer());

        AttributeValueType attributeValue;
        for (Object value : attrib.getValues()) {
            attributeValue = attributeValueBuilder.buildObject();
            attributeValue.setValue(value.toString());
            attribute.getAttributeValues().add(attributeValue);
        }

        return attribute;
    }

    /**
     * Converts a XACML response into a PEP simple-model response.
     * 
     * @param resp XACML response
     * 
     * @return PEP simple-model response
     */
    public static Response toResponse(ResponseType resp) {
        return null;
    }

    static {
        try {
            idGenerator = new SecureRandomIdentifierGenerator();
        } catch (NoSuchAlgorithmException e) {
            // do nothing, all VMs are required to support the default algo
        }

        bodyBuilder = (SOAPObjectBuilder<Body>) Configuration.getBuilderFactory().getBuilder(Body.TYPE_NAME);

        envelopeBuilder = (SOAPObjectBuilder<Envelope>) Configuration.getBuilderFactory()
                .getBuilder(Envelope.TYPE_NAME);

        issuerBuilder = (SAMLObjectBuilder<Issuer>) Configuration.getBuilderFactory().getBuilder(
                Issuer.DEFAULT_ELEMENT_NAME);

        authzDecisionQueryBuilder = (SAMLObjectBuilder<XACMLAuthzDecisionQueryType>) Configuration.getBuilderFactory()
                .getBuilder(XACMLAuthzDecisionQueryType.TYPE_NAME_XACML20);

        requestBuilder = (XACMLObjectBuilder<RequestType>) Configuration.getBuilderFactory().getBuilder(
                RequestType.TYPE_NAME);

        subjectBuilder = (XACMLObjectBuilder<SubjectType>) Configuration.getBuilderFactory().getBuilder(
                SubjectType.TYPE_NAME);

        resourceBuilder = (XACMLObjectBuilder<ResourceType>) Configuration.getBuilderFactory().getBuilder(
                ResourceType.TYPE_NAME);

        resourceContentBuilder = (XACMLObjectBuilder<ResourceContentType>) Configuration.getBuilderFactory()
                .getBuilder(ResourceContentType.TYPE_NAME);

        actionBuilder = (XACMLObjectBuilder<ActionType>) Configuration.getBuilderFactory().getBuilder(
                ActionType.TYPE_NAME);

        enviornmentBuilder = (XACMLObjectBuilder<EnvironmentType>) Configuration.getBuilderFactory().getBuilder(
                EnvironmentType.TYPE_NAME);

        attributeBuilder = (XACMLObjectBuilder<AttributeType>) Configuration.getBuilderFactory().getBuilder(
                AttributeType.TYPE_NAME);

        attributeValueBuilder = (XACMLObjectBuilder<AttributeValueType>) Configuration.getBuilderFactory().getBuilder(
                AttributeValueType.TYPE_NAME);
    }
}