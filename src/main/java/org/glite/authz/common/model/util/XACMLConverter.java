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
 */

package org.glite.authz.common.model.util;

import org.glite.authz.common.model.Action;
import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.AttributeAssignment;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Obligation;
import org.glite.authz.common.model.Request;
import org.glite.authz.common.model.Resource;
import org.glite.authz.common.model.Response;
import org.glite.authz.common.model.Result;
import org.glite.authz.common.model.Status;
import org.glite.authz.common.model.StatusCode;
import org.glite.authz.common.model.Subject;
import org.glite.authz.common.model.util.Strings;
import org.opensaml.Configuration;
import org.opensaml.xacml.XACMLObjectBuilder;
import org.opensaml.xacml.ctx.ActionType;
import org.opensaml.xacml.ctx.AttributeType;
import org.opensaml.xacml.ctx.AttributeValueType;
import org.opensaml.xacml.ctx.DecisionType;
import org.opensaml.xacml.ctx.EnvironmentType;
import org.opensaml.xacml.ctx.RequestType;
import org.opensaml.xacml.ctx.ResourceContentType;
import org.opensaml.xacml.ctx.ResourceType;
import org.opensaml.xacml.ctx.ResponseType;
import org.opensaml.xacml.ctx.ResultType;
import org.opensaml.xacml.ctx.StatusCodeType;
import org.opensaml.xacml.ctx.StatusMessageType;
import org.opensaml.xacml.ctx.StatusType;
import org.opensaml.xacml.ctx.SubjectType;
import org.opensaml.xacml.ctx.DecisionType.DECISION;
import org.opensaml.xacml.policy.AttributeAssignmentType;
import org.opensaml.xacml.policy.EffectType;
import org.opensaml.xacml.policy.ObligationType;
import org.opensaml.xacml.policy.ObligationsType;
import org.opensaml.xml.XMLObjectBuilder;

/**
 * A helper class for converting to/from XACML objects.
 * 
 * <strong>NOTE</strong> the OpenSAML library must already be bootstrapped before any method in this helper class is
 * invoked.
 */
@SuppressWarnings("unchecked")
public class XACMLConverter {

    /** XACML status code builder. */
    private static XACMLObjectBuilder<StatusCodeType> statusCodeBuilder;

    /** XACML status builder. */
    private static XACMLObjectBuilder<StatusType> statusBuilder;

    /** XACML status message builder. */
    private static XMLObjectBuilder<StatusMessageType> statusMessageBuilder;

    /** XACML obligation builder. */
    private static XACMLObjectBuilder<ObligationsType> obligationsBuilder;

    /** XACML obligations builder. */
    private static XACMLObjectBuilder<ObligationType> obligationBuilder;

    /** XACML attribute assignment builder. */
    private static XACMLObjectBuilder<AttributeAssignmentType> attributeAssignmentBuilder;

    /** XACML result builder. */
    private static XACMLObjectBuilder<ResultType> resultBuilder;

    /** XACML decision builder. */
    private static XACMLObjectBuilder<DecisionType> decisionBuilder;

    /** XACML response builder. */
    private static XACMLObjectBuilder<ResponseType> responseBuilder;

    /** XACML attribute builder. */
    private static XACMLObjectBuilder<AttributeType> attributeBuilder;

    /** XACML attribute value builder. */
    private static XACMLObjectBuilder<AttributeValueType> attributeValueBuilder;

    /** XACML action builder. */
    private static XACMLObjectBuilder<ActionType> actionBuilder;

    /** XACML environment builder. */
    private static XACMLObjectBuilder<EnvironmentType> environmentBuilder;

    /** XACML resource builder. */
    private static XACMLObjectBuilder<ResourceType> resourceBuilder;

    /** XACML resource content value builder. */
    private static XACMLObjectBuilder<ResourceContentType> resourceContentBuilder;

    /** XACML subject builder. */
    private static XACMLObjectBuilder<SubjectType> subjectBuilder;

    /** XACML request builder. */
    private static XACMLObjectBuilder<RequestType> requestBuilder;

    static {
        statusCodeBuilder = (XACMLObjectBuilder<StatusCodeType>) Configuration.getBuilderFactory().getBuilder(
                StatusCodeType.DEFAULT_ELEMENT_NAME);
        statusBuilder = (XACMLObjectBuilder<StatusType>) Configuration.getBuilderFactory().getBuilder(
                StatusType.DEFAULT_ELEMENT_NAME);
        statusMessageBuilder = (XMLObjectBuilder<StatusMessageType>) Configuration.getBuilderFactory().getBuilder(
                StatusMessageType.DEFAULT_ELEMENT_NAME);
        obligationsBuilder = (XACMLObjectBuilder<ObligationsType>) Configuration.getBuilderFactory().getBuilder(
                ObligationsType.DEFAULT_ELEMENT_QNAME);
        obligationBuilder = (XACMLObjectBuilder<ObligationType>) Configuration.getBuilderFactory().getBuilder(
                ObligationType.DEFAULT_ELEMENT_QNAME);
        attributeAssignmentBuilder = (XACMLObjectBuilder<AttributeAssignmentType>) Configuration.getBuilderFactory()
                .getBuilder(AttributeAssignmentType.DEFAULT_ELEMENT_NAME);
        resultBuilder = (XACMLObjectBuilder<ResultType>) Configuration.getBuilderFactory().getBuilder(
                ResultType.DEFAULT_ELEMENT_NAME);
        decisionBuilder = (XACMLObjectBuilder<DecisionType>) Configuration.getBuilderFactory().getBuilder(
                DecisionType.DEFAULT_ELEMENT_NAME);
        responseBuilder = (XACMLObjectBuilder<ResponseType>) Configuration.getBuilderFactory().getBuilder(
                ResponseType.DEFAULT_ELEMENT_NAME);
        attributeBuilder = (XACMLObjectBuilder<AttributeType>) Configuration.getBuilderFactory().getBuilder(
                AttributeType.DEFAULT_ELEMENT_NAME);
        attributeValueBuilder = (XACMLObjectBuilder<AttributeValueType>) Configuration.getBuilderFactory().getBuilder(
                AttributeValueType.DEFAULT_ELEMENT_NAME);
        actionBuilder = (XACMLObjectBuilder<ActionType>) Configuration.getBuilderFactory().getBuilder(
                ActionType.DEFAULT_ELEMENT_NAME);
        environmentBuilder = (XACMLObjectBuilder<EnvironmentType>) Configuration.getBuilderFactory().getBuilder(
                EnvironmentType.DEFAULT_ELEMENT_NAME);
        resourceBuilder = (XACMLObjectBuilder<ResourceType>) Configuration.getBuilderFactory().getBuilder(
                ResourceType.DEFAULT_ELEMENT_NAME);
        resourceContentBuilder = (XACMLObjectBuilder<ResourceContentType>) Configuration.getBuilderFactory()
                .getBuilder(ResourceContentType.DEFAULT_ELEMENT_NAME);
        subjectBuilder = (XACMLObjectBuilder<SubjectType>) Configuration.getBuilderFactory().getBuilder(
                SubjectType.DEFAULT_ELEMENT_NAME);
        requestBuilder = (XACMLObjectBuilder<RequestType>) Configuration.getBuilderFactory().getBuilder(
                RequestType.DEFAULT_ELEMENT_NAME);
    }

    /**
     * Converts a XACML {@link ActionType} to a simple model {@link Action}.
     * 
     * @param xacmlAction the XACML action to be converted
     * 
     * @return the simple model object
     */
    public static final Action actionFromXACML(ActionType xacmlAction) {
        if (xacmlAction == null) {
            return null;
        }

        Action action = new Action();
        if (xacmlAction.getAttributes() != null) {
            for (AttributeType xacmlAttribute : xacmlAction.getAttributes()) {
                action.getAttributes().add(attributeFromXACML(xacmlAttribute));
            }
        }

        return action;
    }

    /**
     * Converts a {@link Action} to a XACML {@link ActionType}.
     * 
     * @param action the simple model action to be converted
     * 
     * @return the XACML object
     */
    public static final ActionType actionToXACML(Action action) {
        if (action == null) {
            return null;
        }

        ActionType xacmlAction = actionBuilder.buildObject();
        if (action.getAttributes() != null) {
            for (Attribute attribute : action.getAttributes()) {
                xacmlAction.getAttributes().add(attributeToXACML(attribute));
            }
        }

        return xacmlAction;
    }

    /**
     * Converts a XACML {@link AttributeType} to a simple model {@link Attribute}.
     * 
     * @param xacmlAttribute the XACML attribute to be converted
     * 
     * @return the simple model object
     */
    public static final Attribute attributeFromXACML(AttributeType xacmlAttribute) {
        if (xacmlAttribute == null) {
            return null;
        }

        Attribute attribute = new Attribute();

        attribute.setDataType(Strings.safeTrimOrNullString(xacmlAttribute.getDataType()));
        attribute.setId(Strings.safeTrimOrNullString(xacmlAttribute.getAttributeID()));
        attribute.setIssuer(Strings.safeTrimOrNullString(xacmlAttribute.getIssuer()));

        if (xacmlAttribute.getAttributeValues() != null) {
            for (AttributeValueType xacmlAttributeValue : xacmlAttribute.getAttributeValues()) {
                // null value are not valid in Hessian
                String value= xacmlAttributeValue.getValue();
                if (value != null) {
                    attribute.getValues().add(Strings.safeTrimOrNullString(xacmlAttributeValue.getValue()));
                }
            }
        }

        return attribute;
    }

    /**
     * Converts a {@link Attribute} to a XACML {@link AttributeType}. Attribute values are converted to string by means
     * of the {@link Object#toString()} method.
     * 
     * @param attribute the simple model attribute to be converted
     * 
     * @return the XACML object
     */
    public static final AttributeType attributeToXACML(Attribute attribute) {
        if (attribute == null) {
            return null;
        }

        AttributeType xacmlAttribute = attributeBuilder.buildObject();

        xacmlAttribute.setAttributeID(Strings.safeTrimOrNullString(attribute.getId()));

        String datatype = Strings.safeTrimOrNullString(attribute.getDataType());
        if (datatype != null) {
            xacmlAttribute.setDataType(datatype);
        } else {
            xacmlAttribute.setDataType(Attribute.DT_STRING);
        }

        xacmlAttribute.setIssuer(Strings.safeTrimOrNullString(attribute.getIssuer()));

        if (attribute.getValues() != null) {
            AttributeValueType xacmlAttributeValue;
            for (Object attributeValue : attribute.getValues()) {
                String value= Strings.safeTrimOrNullString(attributeValue.toString());
                if (value != null) {
                    xacmlAttributeValue = attributeValueBuilder.buildObject();
                    xacmlAttributeValue.setValue(value);
                    xacmlAttribute.getAttributeValues().add(xacmlAttributeValue);
                }
            }
        }

        return xacmlAttribute;
    }

    /**
     * Converts a XACML {@link EnvironmentType} to a simple model {@link Environment}.
     * 
     * @param xacmlEnvironment the XACML environment to be converted
     * 
     * @return the simple model object
     */
    public static final Environment environmentFromXACML(EnvironmentType xacmlEnvironment) {
        if (xacmlEnvironment == null) {
            return null;
        }

        Environment environment = new Environment();
        if (xacmlEnvironment.getAttributes() != null) {
            for (AttributeType xacmlAttribute : xacmlEnvironment.getAttributes()) {
                environment.getAttributes().add(attributeFromXACML(xacmlAttribute));
            }
        }

        return environment;
    }

    /**
     * Converts a {@link Environment} to a XACML {@link EnvironmentType}.
     * 
     * @param environment the simple model environment to be converted
     * 
     * @return the XACML object
     */
    public static final EnvironmentType environmentToXACML(Environment environment) {
        if (environment == null) {
            return null;
        }

        EnvironmentType xacmlEnvironment = environmentBuilder.buildObject();
        if (environment.getAttributes() != null) {
            for (Attribute attribute : environment.getAttributes()) {
                xacmlEnvironment.getAttributes().add(attributeToXACML(attribute));
            }
        }

        return xacmlEnvironment;
    }

    /**
     * Converts a XACML {@link ObligationType} to a simple model {@link Obligation}. Note, this conversion only supports
     * string content attribute assignments.
     * 
     * @param xacmlObligation the XACML obligations to be converted
     * 
     * @return the simple model object
     */
    public static final Obligation obligationFromXACML(ObligationType xacmlObligation) {
        if (xacmlObligation == null) {
            return null;
        }

        Obligation obligation = new Obligation();

        AttributeAssignment attributeAssignment;
        if (xacmlObligation.getAttributeAssignments() != null) {
            for (AttributeAssignmentType xacmlAttributeAssignment : xacmlObligation.getAttributeAssignments()) {
                attributeAssignment = new AttributeAssignment();
                attributeAssignment.setAttributeId(Strings.safeTrimOrNullString(xacmlAttributeAssignment
                        .getAttributeId()));
                attributeAssignment.setDataType(Strings.safeTrimOrNullString(xacmlAttributeAssignment.getDataType()));
                attributeAssignment.setValue(Strings.safeTrimOrNullString(xacmlAttributeAssignment.getValue()));
            }
        }

        switch (xacmlObligation.getFulfillOn()) {
            case Deny:
                obligation.setFulfillOn(Result.DECISION_DENY);
                break;
            case Permit:
                obligation.setFulfillOn(Result.DECISION_PERMIT);
                break;
        }

        obligation.setId(Strings.safeTrimOrNullString(xacmlObligation.getObligationId()));

        return obligation;
    }

    /**
     * Converts a simple model {@link Obligation} in to a XACML {@link ObligationType}. Multi-value attribute
     * assignments are not supported.
     * 
     * @param obligation the simple model obligation to convert
     * 
     * @return the XACML object
     */
    public static final ObligationType obligationToXACML(Obligation obligation) {
        if (obligation == null) {
            return null;
        }

        ObligationType xacmlObligation = obligationBuilder.buildObject();

        AttributeAssignmentType xacmlAttributeAssignment;
        if (obligation.getAttributeAssignments() != null) {
            for (AttributeAssignment attributeAssignment : obligation.getAttributeAssignments()) {
                attributeAssignment = obligation.getAttributeAssignments().get(0);
                xacmlAttributeAssignment = attributeAssignmentBuilder.buildObject();
                xacmlAttributeAssignment.setAttributeId(Strings.safeTrimOrNullString(attributeAssignment
                        .getAttributeId()));
                xacmlAttributeAssignment.setDataType(attributeAssignment.getDataType());
                xacmlAttributeAssignment.setValue(attributeAssignment.getValue());
            }
        }

        if (obligation.getFulfillOn() == Result.DECISION_PERMIT) {
            xacmlObligation.setFulfillOn(EffectType.Permit);
        } else {
            xacmlObligation.setFulfillOn(EffectType.Deny);
        }

        xacmlObligation.setObligationId(Strings.safeTrimOrNullString(obligation.getId()));

        return xacmlObligation;
    }

    /**
     * Converts a XACML {@link RequestType} to a simple model {@link Request}.
     * 
     * @param xacmlRequest the XACML request to be converted
     * 
     * @return the simple model object
     */
    public static final Request requestFromXACML(RequestType xacmlRequest) {
        Request request = new Request();

        request.setAction(actionFromXACML(xacmlRequest.getAction()));
        request.setEnvironment(environmentFromXACML(xacmlRequest.getEnvironment()));

        if (xacmlRequest.getResources() != null) {
            for (ResourceType xacmlResource : xacmlRequest.getResources()) {
                request.getResources().add(resourceFromXACML(xacmlResource));
            }
        }

        if (xacmlRequest.getSubjects() != null) {
            for (SubjectType xacmlSubject : xacmlRequest.getSubjects()) {
                request.getSubjects().add(subjectFromXACML(xacmlSubject));
            }
        }

        return request;
    }

    /**
     * Converts a {@link Request} to a XACML {@link RequestType}.
     * 
     * @param request the simple model request to be converted
     * 
     * @return the XACML object
     */
    public static final RequestType requestToXACML(Request request) {
        if (request == null) {
            return null;
        }

        RequestType xacmlRequest = requestBuilder.buildObject();
        xacmlRequest.setAction(actionToXACML(request.getAction()));
        xacmlRequest.setEnvironment(environmentToXACML(request.getEnvironment()));

        if (request.getResources() != null) {
            for (Resource resource : request.getResources()) {
                xacmlRequest.getResources().add(resourceToXACML(resource));
            }
        }

        if (request.getSubjects() != null) {
            for (Subject subject : request.getSubjects()) {
                xacmlRequest.getSubjects().add(subjectToXACML(subject));
            }
        }

        return xacmlRequest;
    }

    /**
     * Converts a XACML {@link ResourceType} to a simple model {@link Resource}. Only simple strings are supported as
     * resource content values.
     * 
     * @param xacmlResource the XACML resource to be converted
     * 
     * @return the simple model object
     */
    public static final Resource resourceFromXACML(ResourceType xacmlResource) {
        if (xacmlResource == null) {
            return null;
        }

        Resource resource = new Resource();

        if (xacmlResource.getResourceContent() != null) {
            resource.setResourceContent(Strings.safeTrimOrNullString(xacmlResource.getResourceContent().getValue()));
        }

        if (xacmlResource.getAttributes() != null) {
            for (AttributeType xacmlAttribute : xacmlResource.getAttributes()) {
                resource.getAttributes().add(attributeFromXACML(xacmlAttribute));
            }
        }

        return resource;
    }

    /**
     * Converts a {@link Resource} to a XACML {@link ResourceType}.
     * 
     * @param resource the simple model resource to be converted
     * 
     * @return the XACML object
     */
    public static final ResourceType resourceToXACML(Resource resource) {
        if (resource == null) {
            return null;
        }

        ResourceType xacmlResource = resourceBuilder.buildObject();

        if (!Strings.isEmpty(resource.getResourceContent())) {
            ResourceContentType xacmlResourceContent = resourceContentBuilder.buildObject();
            xacmlResourceContent.setValue(Strings.safeTrimOrNullString(resource.getResourceContent()));
            xacmlResource.setResourceContent(xacmlResourceContent);
        }

        if (resource.getAttributes() != null) {
            for (Attribute attribute : resource.getAttributes()) {
                xacmlResource.getAttributes().add(attributeToXACML(attribute));
            }
        }

        return xacmlResource;
    }

    /**
     * Converts a XACML {@link ResponseType} to a simple model {@link Response}.
     * 
     * @param xacmlResponse the XACML response to be converted
     * @param xacmlRequest the XACML request which rendered the given response, may be null
     * 
     * @return the simple model object
     */
    public static final Response responseFromXACML(ResponseType xacmlResponse, RequestType xacmlRequest) {
        if (xacmlResponse == null) {
            return null;
        }

        Response response = new Response();

        response.getResults().add(resultFromXACML(xacmlResponse.getResult()));

        if (xacmlRequest != null) {
            response.setRequest(requestFromXACML(xacmlRequest));
        }

        return response;
    }

    /**
     * Converts a {@link Response} to a XACML {@link ResponseType}. If the response contains a {@link Request} it must
     * be converted separately. Only the first {@link Result} in the response is converted.
     * 
     * @param response the simple model response to be converted
     * 
     * @return the XACML object
     */
    public static final ResponseType responseToXACML(Response response) {
        if (response == null) {
            return null;
        }

        ResponseType xacmlResponse = responseBuilder.buildObject();
        xacmlResponse.setResult(resultToXACML(response.getResults().get(0)));
        return xacmlResponse;
    }

    /**
     * Converts a XACML {@link ResultType} to a simple model {@link Result}.
     * 
     * @param xacmlResult the XACML result to be converted
     * 
     * @return the simple model object
     */
    public static final Result resultFromXACML(ResultType xacmlResult) {
        if (xacmlResult == null) {
            return null;
        }

        Result result = new Result();
        
        result.setResourceId(xacmlResult.getResourceId());

        switch (xacmlResult.getDecision().getDecision()) {
            case Deny:
                result.setDecision(Result.DECISION_DENY);
                break;
            case Indeterminate:
                result.setDecision(Result.DECISION_INDETERMINATE);
                break;
            case NotApplicable:
                result.setDecision(Result.DECISION_NOT_APPLICABLE);
                break;
            case Permit:
                result.setDecision(Result.DECISION_PERMIT);
                break;
        }

        result.setStatus(statusFromXACML(xacmlResult.getStatus()));

        if (xacmlResult.getObligations() != null && xacmlResult.getObligations().getObligations() != null) {
            for (ObligationType xacmlObligation : xacmlResult.getObligations().getObligations()) {
                result.getObligations().add(obligationFromXACML(xacmlObligation));
            }
        }

        return result;
    }

    /**
     * Converts a simple model {@link Result} in to a XACML {@link ResultType}.
     * 
     * @param result the simple model result to convert
     * 
     * @return the XACML object
     */
    public static final ResultType resultToXACML(Result result) {
        if (result == null) {
            return null;
        }

        ResultType xacmlResult = resultBuilder.buildObject();

        DecisionType decision = decisionBuilder.buildObject();
        switch (result.getDecision()) {
            case Result.DECISION_DENY:
                decision.setDecision(DECISION.Deny);
                break;
            case Result.DECISION_INDETERMINATE:
                decision.setDecision(DECISION.Indeterminate);
                break;
            case Result.DECISION_NOT_APPLICABLE:
                decision.setDecision(DECISION.NotApplicable);
                break;
            case Result.DECISION_PERMIT:
                decision.setDecision(DECISION.Permit);
                break;
        }
        xacmlResult.setDecision(decision);

        xacmlResult.setStatus(statusToXACML(result.getStatus()));

        if (result.getObligations() != null) {
            ObligationsType xacmlObligations = obligationsBuilder.buildObject();
            for (Obligation obligation : result.getObligations()) {
                xacmlObligations.getObligations().add(obligationToXACML(obligation));
            }
            xacmlResult.setObligations(xacmlObligations);
        }

        return xacmlResult;
    }

    /**
     * Converts a XACML {@link StatusCodeType} to a simple model {@link StatusCode}.
     * 
     * @param xacmlStatusCode the XACML status code to be converted
     * 
     * @return the simple model object
     */
    public static final StatusCode statusCodeFromXACML(StatusCodeType xacmlStatusCode) {
        if (xacmlStatusCode == null) {
            return null;
        }

        StatusCode statusCode = new StatusCode();
        statusCode.setCode(Strings.safeTrimOrNullString(xacmlStatusCode.getValue()));
        statusCode.setSubCode(statusCodeFromXACML(xacmlStatusCode.getStatusCode()));
        return statusCode;
    }

    /**
     * Converts a simple model {@link StatusCode} in to a XACML {@link StatusCodeType}.
     * 
     * @param statusCode the simple model status code to convert
     * 
     * @return the XACML object
     */
    public static final StatusCodeType statusCodeToXACML(StatusCode statusCode) {
        if (statusCode == null) {
            return null;
        }

        StatusCodeType xacmlStatusCode = statusCodeBuilder.buildObject();
        xacmlStatusCode.setValue(Strings.safeTrimOrNullString(statusCode.getCode()));
        xacmlStatusCode.setStatusCode(statusCodeToXACML(statusCode.getSubCode()));
        return xacmlStatusCode;
    }

    /**
     * Converts a XACML {@link StatusType} to a simple model {@link Status}. Note, this conversion does not support the
     * XACML status details.
     * 
     * @param xacmlStatus the XACML status to be converted
     * 
     * @return the simple model object
     */
    public static final Status statusFromXACML(StatusType xacmlStatus) {
        if (xacmlStatus == null) {
            return null;
        }

        Status status = new Status();
        status.setCode(statusCodeFromXACML(xacmlStatus.getStatusCode()));
        if (xacmlStatus.getStatusMessage() != null) {
            status.setMessage(Strings.safeTrimOrNullString(xacmlStatus.getStatusMessage().getValue()));
        }

        return status;
    }

    /**
     * Converts a simple model {@link Status} in to a XACML {@link StatusType}.
     * 
     * @param status the simple model status to convert
     * 
     * @return the XACML object
     */
    public static final StatusType statusToXACML(Status status) {
        if (status == null) {
            return null;
        }

        StatusType xacmlStatus = statusBuilder.buildObject();
        xacmlStatus.setStatusCode(statusCodeToXACML(status.getCode()));

        if (!Strings.isEmpty(status.getMessage())) {
            StatusMessageType xacmlStatusMessage = statusMessageBuilder.buildObject(
                    StatusMessageType.DEFAULT_ELEMENT_NAME, StatusMessageType.TYPE_NAME);
            xacmlStatusMessage.setValue(Strings.safeTrimOrNullString(status.getMessage()));
            xacmlStatus.setStatusMessage(xacmlStatusMessage);
        }

        return xacmlStatus;
    }

    /**
     * Converts a XACML {@link SubjectType} to a simple model {@link Subject}.
     * 
     * @param xacmlSubject the XACML subject to be converted
     * 
     * @return the simple model object
     */
    public static final Subject subjectFromXACML(SubjectType xacmlSubject) {
        if (xacmlSubject == null) {
            return null;
        }

        Subject subject = new Subject();
        subject.setCategory(Strings.safeTrimOrNullString(xacmlSubject.getSubjectCategory()));
        if (xacmlSubject.getAttributes() != null) {
            for (AttributeType xacmlAttribute : xacmlSubject.getAttributes()) {
                subject.getAttributes().add(attributeFromXACML(xacmlAttribute));
            }
        }

        return subject;
    }

    /**
     * Converts a {@link Subject} to a XACML {@link SubjectType}.
     * 
     * @param subject the simple model subject to be converted
     * 
     * @return the XACML object
     */
    public static final SubjectType subjectToXACML(Subject subject) {
        if (subject == null) {
            return null;
        }

        SubjectType xacmlSubject = subjectBuilder.buildObject();
        xacmlSubject.setSubjectCategory(Strings.safeTrimOrNullString(subject.getCategory()));
        if (subject.getAttributes() != null) {
            for (Attribute attribute : subject.getAttributes()) {
                xacmlSubject.getAttributes().add(attributeToXACML(attribute));
            }
        }

        return xacmlSubject;
    }
}