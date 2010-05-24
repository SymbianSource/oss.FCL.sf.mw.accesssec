/*
* Copyright (c) 2009 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:
* This is the header file for testing EAP Configuration Interface.
*/

/*
 * %version: 5 %
 */

#ifndef TESTQTCONFIGUTILS_H_
#define TESTQTCONFIGUTILS_H_

// System includes
#include <QObject>

// User includes

// Forward declarations
class QSignalSpy;
class EapQtConfigInterface;
class EapQtPluginHandle;
class EapQtCertificateInfo;
class CmManagerShim;
class CmConnectionMethodShim;

// External data types

// Constants

class TestQtConfigUtils: public QObject
{
    Q_OBJECT
    
private slots:

    // Functions from QTest framework.
    void initTestCase();
    void cleanupTestCase();
    void init();
    void cleanup();

#if 1
    // test EapQtPluginInfo
    void testEapQtPluginInfoPluginUndefined();
    void testEapQtPluginInfoPluginEapAka();
    void testEapQtPluginInfoPluginEapFast();
    void testEapQtPluginInfoPluginEapGtc();
    void testEapQtPluginInfoPluginLeap();
    void testEapQtPluginInfoPluginEapMschapv2();
    void testEapQtPluginInfoPluginPeap();
    void testEapQtPluginInfoPluginEapSim();
    void testEapQtPluginInfoPluginEapTls();
    void testEapQtPluginInfoPluginEapTtls();
    void testEapQtPluginInfoPluginPap();
    void testEapQtPluginInfoPluginPlainMschapv2();
    void testEapQtPluginInfoAssignment();
    void testEapQtPluginInfoSelfAssignment();

    // test EapQtPluginHandle (for coverage in addition to the onces above)
    void testEapQtPluginHandleDefaultConstructor();
    void testEapQtExpandedEapTypeLastConstructor();
    void testEapQtPluginHandlePluginLastConstructor();
    void testEapQtPluginHandleEapTypeConstructor();
    void testEapQtPluginHandleEapTypeUidConstructor();
    void testEapQtPluginHandleSelfAssignment();

    // test EapQtExpandedEapType (for coverage in addition to the onces above)
    void testEapQtExpandedEapTypeDefaultConstructor();
    void testEapQtExpandedEapTypeConstructorWpsType();
    void testEapQtExpandedEapTypeConstructorWpsByteArray();
    void testEapQtExpandedEapTypeAssignment();
    void testEapQtExpandedEapTypeSelfAssignment();

    // test EapQtConfigInterface
    void testDefaultConstructor();
    void testConstructorThrowing();
    void testParallelInstances();
    void testSetConfigurationReferenceUndefinedAgain();
    void testSetConfigurationReferenceFailure();
    void testCertificateAuthorityCertificates();
    void testUserCertificates();
    void testSupportedOuterTypes();
    void testSupportedInnerTypesPeap();
    void testIsSupportedOuterTypePeap();
    void testIsSupportedInnerTypePeap();
    // this must be executed before the rest of the tests
    void testSetConfigurationReferenceValidWlanIap();
    void testTestAgainForValidWlanIap();
    void testSelectedOuterTypes();
    void testIsSupportedTypeNewInstance();
    void testSaveConfigurationFull();
    void testSaveConfigurationEapTtls();
#endif

    void testUiInstance();
    
private:

private:
    EapQtConfigInterface* mEapConfigIf;
    QList<EapQtCertificateInfo> mCaCertInfo;
    QList<EapQtCertificateInfo> mUserCertInfo;
    CmManagerShim* mCmm;
    CmConnectionMethodShim* mCmmShim;

};

#endif /* TESTQTCONFIGUTILS_H_ */

