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

package org.glite.authz.pep.pip.provider;

import java.util.GregorianCalendar;
import java.util.TimeZone;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import net.jcip.annotations.ThreadSafe;

import org.glite.authz.common.model.Attribute;
import org.glite.authz.common.model.Environment;
import org.glite.authz.common.model.Request;
import org.glite.authz.pep.pip.PIPProcessingException;

/**
 * A PIP the adds the time (in UTC), at invocation, as the environment variables current-time, current-date, and
 * current-dateTime.
 */
@ThreadSafe
public class EnvironmentTimePIP extends AbstractPolicyInformationPoint {

    /** Name of the current time attribute. */
    public static final String CURRENT_TIME_ATTRIB_NAME = "urn:oasis:names:tc:xacml:1.0:environment:current-time";

    /** Name of the current date attribute. */
    public static final String CURRENT_DATE_ATTRIB_NAME = "urn:oasis:names:tc:xacml:1.0:environment:current-date";

    /** Name of the current date/time attribute. */
    public static final String CURRENT_DATETIME_ATTRIB_NAME = "urn:oasis:names:tc:xacml:1.0:environment:current-dateTime";

    /** XML calendar data type factory. */
    private DatatypeFactory xmlCalendarFactory;

    /**
     * Constructor.
     * 
     * @param pipId ID of the PIP
     */
    public EnvironmentTimePIP(String pipId) {
        super(pipId);

        try {
            xmlCalendarFactory = DatatypeFactory.newInstance();
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException("JAXP provider does not provide a complete JAXP 1.3 implementation", e);
        }
    }

    /** {@inheritDoc} */
    public boolean populateRequest(Request request) throws PIPProcessingException {
        Environment environment = request.getEnvironment();
        if(environment == null){
            environment = new Environment();
            request.setEnvironment(environment);
        }
        
        GregorianCalendar now = new GregorianCalendar(TimeZone.getTimeZone("UTC"));

        XMLGregorianCalendar currentTime = xmlCalendarFactory.newXMLGregorianCalendar(now);
        currentTime.setYear(DatatypeConstants.FIELD_UNDEFINED);
        currentTime.setMonth(DatatypeConstants.FIELD_UNDEFINED);
        currentTime.setDay(DatatypeConstants.FIELD_UNDEFINED);
        currentTime.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        Attribute currentTimeAttribute = new Attribute();
        currentTimeAttribute.setId(CURRENT_TIME_ATTRIB_NAME);
        currentTimeAttribute.setDataType(Attribute.DT_TIME);
        currentTimeAttribute.getValues().add(currentTime.toXMLFormat());
        environment.getAttributes().add(currentTimeAttribute);

        XMLGregorianCalendar currentDate = xmlCalendarFactory.newXMLGregorianCalendar(now);
        currentDate.setHour(DatatypeConstants.FIELD_UNDEFINED);
        currentDate.setMinute(DatatypeConstants.FIELD_UNDEFINED);
        currentDate.setSecond(DatatypeConstants.FIELD_UNDEFINED);
        currentDate.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        Attribute currentDateAttribute = new Attribute();
        currentDateAttribute.setId(CURRENT_DATE_ATTRIB_NAME);
        currentDateAttribute.setDataType(Attribute.DT_DATE);
        currentDateAttribute.getValues().add(currentDate.toXMLFormat());
        environment.getAttributes().add(currentDateAttribute);

        XMLGregorianCalendar currentDateTime = xmlCalendarFactory.newXMLGregorianCalendar(now);
        currentDateTime.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
        Attribute currentDateTimeAttribute = new Attribute();
        currentDateTimeAttribute.setId(CURRENT_DATETIME_ATTRIB_NAME);
        currentDateTimeAttribute.setDataType(Attribute.DT_DATE_TIME);
        currentDateTimeAttribute.getValues().add(currentDateTime.toXMLFormat());
        environment.getAttributes().add(currentDateTimeAttribute);

        return true;
    }
}