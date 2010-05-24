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
 * This is the source file for testing EAP Configuration Interface.
 */

/*
 * %version: 8 %
 */

#ifdef INCLUDE_UI_CASES
#warning UI cases included, cases cannot be run in Emulator textshell.
#endif

// System includes
#include <QtCore>
#include <QTest>
#include <cmmanager_shim.h>
#include <cmmanagerdefines_shim.h>
#include <cmconnectionmethod_shim.h>
#include <eapqtconfiginterface.h>
#include <eapqtplugininfo.h>
#include <eapqtvalidator.h>
#include <eapqtpluginhandle.h>
#include <eapqtexpandedeaptype.h>
#include <eapqtcertificateinfo.h>

#ifdef INCLUDE_UI_CASES
#include <cpbasesettingview.h>
#endif

// User includes
#include "testqtconfigutils.h"

// External function prototypes

// Local constants
static const int global_pluginOrder = 10;
static const char global_wpsType[] = { 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01 };
static const int global_invalidIap = 9999;
static int global_undefinedIap = EapQtConfigInterface::IapIdUndefined;
static int global_wlanIap = -2;

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

// ---------------------------------------------------------
// FRAMEWORK FUNCTIONS
// ---------------------------------------------------------

/**
 * This function will be called before the first test function is executed.
 */
void TestQtConfigUtils::initTestCase()
{
    mEapConfigIf = new EapQtConfigInterface(EapQtConfigInterface::EapBearerTypeWlan,
        global_undefinedIap);

    mCmm = new CmManagerShim();
    mCmmShim = mCmm->createConnectionMethod(CMManagerShim::BearerTypeWlan);
    mCmmShim->setStringAttribute(CMManagerShim::CmName, QString("EAP unit test"));
    mCmmShim->update();
    global_wlanIap = mCmmShim->getIntAttribute(CMManagerShim::CmIapId);
}

/**
 * This function will be called after the last test function was executed.
 */
void TestQtConfigUtils::cleanupTestCase()
{
    qDebug("calling mEapConfigIf->setConfigurationReference(global_wlanIap)");
    mEapConfigIf->setConfigurationReference(global_wlanIap);

    qDebug("calling mEapConfigIf->deleteConfiguration()");
    mEapConfigIf->deleteConfiguration();

    qDebug("calling delete mEapConfigIf");
    delete mEapConfigIf;

    qDebug("calling mCmmShim->deleteConnectionMethod()");

    int error;
    try {
        mCmmShim->deleteConnectionMethod();
    } catch (const std::exception &ex) {
        error = qt_symbian_exception2Error(ex);
        qDebug("mCmmShim->deleteConnectionMethod() failed with error: %d", error);
    }

    qDebug("calling delete mCmmShim");
    try {
        delete mCmmShim;
    } catch (const std::exception &ex) {
        error = qt_symbian_exception2Error(ex);
        qDebug("delete mCmmShim failed with error: ", error);
    }

    delete mCmm;
}

/**
 * This function will be called before each test function is executed.
 */
void TestQtConfigUtils::init()
{

}

/**
 * This function will be called after each test function is executed.
 */
void TestQtConfigUtils::cleanup()
{

}

// ---------------------------------------------------------
// TEST CASES
// ---------------------------------------------------------

// ---------------------------------------------------------
// test EapQtPluginInfo
// ---------------------------------------------------------
#if 1
void TestQtConfigUtils::testEapQtPluginInfoPluginUndefined()
{
    QString pluginName("PluginUndefined");
    EapQtPluginInfo info(EapQtPluginHandle::PluginUndefined, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginUndefined);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapAka()
{
    QString pluginName("PluginEapAka");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapAka, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapAka);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapFast()
{
    QString pluginName("PluginEapFast");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapFast, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapFast);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapGtc()
{
    QString pluginName("PluginEapGtc");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapGtc, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapGtc);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginLeap()
{
    QString pluginName("PluginLeap");
    EapQtPluginInfo info(EapQtPluginHandle::PluginLeap, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginLeap);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapMschapv2()
{
    QString pluginName("PluginEapMschapv2");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapMschapv2, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapMschapv2);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginPeap()
{
    QString pluginName("PluginPeap");
    EapQtPluginInfo info(EapQtPluginHandle::PluginPeap, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginPeap);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapSim()
{
    QString pluginName("PluginEapSim");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapSim, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapSim);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapTls()
{
    QString pluginName("PluginEapTls");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapTls, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapTls);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginEapTtls()
{
    QString pluginName("PluginEapTtls");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapTtls, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapTtls);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginPap()
{
    QString pluginName("PluginPap");
    EapQtPluginInfo info(EapQtPluginHandle::PluginPap, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginPap);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoPluginPlainMschapv2()
{
    QString pluginName("PluginPlainMschapv2");
    EapQtPluginInfo info(EapQtPluginHandle::PluginPlainMschapv2, pluginName, global_pluginOrder);
    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginPlainMschapv2);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

void TestQtConfigUtils::testEapQtPluginInfoAssignment()
{
    QString pluginName1("PluginPlainMschapv2");
    QString pluginName2("PluginEapTtls");

    EapQtPluginInfo info1(EapQtPluginHandle::PluginPlainMschapv2, pluginName1, global_pluginOrder);
    EapQtPluginInfo info2(EapQtPluginHandle::PluginEapTtls, pluginName2, global_pluginOrder + 1);

    info1 = info2;

    QVERIFY(info1.pluginHandle() == info2.pluginHandle());
    QVERIFY(info1.localizationId() == info2.localizationId());
    QVERIFY(info1.orderNumber() == info2.orderNumber());
}

void TestQtConfigUtils::testEapQtPluginInfoSelfAssignment()
{
    QString pluginName("PluginEapSim");
    EapQtPluginInfo info(EapQtPluginHandle::PluginEapSim, pluginName, global_pluginOrder);
    info = info;

    QVERIFY(info.pluginHandle() == EapQtPluginHandle::PluginEapSim);
    QVERIFY(info.localizationId() == pluginName);
    QVERIFY(info.orderNumber() == global_pluginOrder);
}

// ---------------------------------------------------------
// test EapQtPluginHandle
// ---------------------------------------------------------

void TestQtConfigUtils::testEapQtPluginHandleDefaultConstructor()
{
    EapQtPluginHandle handle;
    QVERIFY(handle == EapQtPluginHandle::PluginUndefined);
}

void TestQtConfigUtils::testEapQtPluginHandlePluginLastConstructor()
{
    EapQtPluginHandle handle(EapQtPluginHandle::PluginLast);
    QVERIFY(handle.pluginId() == EapQtPluginHandle::PluginUndefined);
}

void TestQtConfigUtils::testEapQtPluginHandleEapTypeConstructor()
{
    EapQtPluginHandle handle(EapQtExpandedEapType::TypeEapAka);
    QVERIFY(handle.pluginId() == EapQtPluginHandle::PluginEapAka);
}

void TestQtConfigUtils::testEapQtPluginHandleEapTypeUidConstructor()
{
    int uid(0x12345678);
    EapQtPluginHandle handle(EapQtExpandedEapType::TypePeap, uid);
    QVERIFY(handle.pluginId() == EapQtPluginHandle::PluginPeap);
    QVERIFY(handle.protocolImplementationUid() == uid);
}

void TestQtConfigUtils::testEapQtPluginHandleSelfAssignment()
{
    EapQtPluginHandle handle(EapQtPluginHandle::PluginEapTls);
    handle = handle;
    QVERIFY(handle.pluginId() == EapQtPluginHandle::PluginEapTls);
}

// ---------------------------------------------------------
// test EapQtExpandedEapType
// ---------------------------------------------------------

void TestQtConfigUtils::testEapQtExpandedEapTypeDefaultConstructor()
{
    EapQtExpandedEapType eapType;
    QVERIFY(eapType.type() == EapQtExpandedEapType::TypeUndefined);
    QVERIFY(eapType.eapExpandedData().count() == 0);
}

void TestQtConfigUtils::testEapQtExpandedEapTypeLastConstructor()
{
    EapQtExpandedEapType eapType(EapQtExpandedEapType::TypeLast);
    QVERIFY(eapType.type() == EapQtExpandedEapType::TypeUndefined);
}

void TestQtConfigUtils::testEapQtExpandedEapTypeConstructorWpsType()
{
    EapQtExpandedEapType eapType(EapQtExpandedEapType::TypeProtectedSetup);
    QVERIFY(eapType.type() == EapQtExpandedEapType::TypeProtectedSetup);
    QVERIFY(eapType.eapExpandedData() == QByteArray(global_wpsType, sizeof(global_wpsType)));
}

void TestQtConfigUtils::testEapQtExpandedEapTypeConstructorWpsByteArray()
{
    QByteArray wpsArray(global_wpsType, sizeof(global_wpsType));
    EapQtExpandedEapType eapType(wpsArray);

    QVERIFY(eapType.type() == EapQtExpandedEapType::TypeProtectedSetup);
    QVERIFY(eapType.eapExpandedData() == wpsArray);
}

void TestQtConfigUtils::testEapQtExpandedEapTypeAssignment()
{
    EapQtExpandedEapType eapType1;
    EapQtExpandedEapType eapType2(EapQtExpandedEapType::TypePlainMschapv2);
    eapType1 = eapType2;

    QVERIFY(eapType1.type() == eapType2.type());
    QVERIFY(eapType1.eapExpandedData() == eapType2.eapExpandedData());
    QVERIFY(eapType1 == eapType2);
}

void TestQtConfigUtils::testEapQtExpandedEapTypeSelfAssignment()
{
    EapQtExpandedEapType eapType(EapQtExpandedEapType::TypeEapTtls);
    eapType = eapType;

    QVERIFY(eapType == EapQtExpandedEapType::TypeEapTtls);
    // to test != operator as well
    QVERIFY(eapType != EapQtExpandedEapType::TypeUndefined);
}

// ---------------------------------------------------------
// test EapQtConfigInterface
// ---------------------------------------------------------

void TestQtConfigUtils::testDefaultConstructor()
{
    EapQtConfigInterface localEapConfigIf;

    QScopedPointer<EapQtValidator> val(localEapConfigIf.validatorEap(
        EapQtExpandedEapType::TypeEapAka, EapQtConfig::Username));

    EapQtValidator::Status status = val->validate(QString("test"));
    QVERIFY(status == EapQtValidator::StatusOk);

    status = val->validate(QString());
    QVERIFY(status == EapQtValidator::StatusOk);

    status = val->validate(QByteArray());
    QVERIFY(status == EapQtValidator::StatusInvalid);

    status = val->validate(QString("pwd@realm"));
    QVERIFY(status == EapQtValidator::StatusInvalidCharacters);

    status = val->validate(QString("@"));
    QVERIFY(status == EapQtValidator::StatusInvalidCharacters);

    status = val->validate(QString("X"));
    QVERIFY(status == EapQtValidator::StatusOk);

    status = val->validate(QString("uSerNäme"));
    QVERIFY(status == EapQtValidator::StatusOk);

    status = val->validate(QString("as0d7fg9µ8a&&¤%GSB*^ü~||><:M;_-§][6{]{[]£"));
    QVERIFY(status == EapQtValidator::StatusOk);

    QString veryLong(254, QChar('Z'));

    status = val->validate(veryLong);
    QVERIFY(status == EapQtValidator::StatusOk);

    veryLong.append("}");

    status = val->validate(veryLong);
    QVERIFY(status == EapQtValidator::StatusOk);

    veryLong.append("K");

    status = val->validate(veryLong);
    QVERIFY(status == EapQtValidator::StatusTooLong);

    // this one should throw since not supported for validator instance
    bool pass(false);
    try {
        localEapConfigIf.setConfigurationReference(global_wlanIap);
    } catch (const std::exception&) {
        pass = true;
    }
    QVERIFY(pass == true);
}

void TestQtConfigUtils::testParallelInstances()
{
    EapQtConfigInterface localEapConfigIf(EapQtConfigInterface::EapBearerTypeWlan,
        global_undefinedIap);
    QVERIFY(localEapConfigIf.isSupportedOuterType(EapQtPluginHandle::PluginEapAka) == true);
    QVERIFY(mEapConfigIf->isSupportedOuterType(EapQtPluginHandle::PluginPeap) == true);
}

void TestQtConfigUtils::testConstructorThrowing()
{
    // this one should throw since IAP id is invalid
    bool pass(false);
    try {
        EapQtConfigInterface localEapConfigIf(EapQtConfigInterface::EapBearerTypeWlan,
            global_invalidIap);
    } catch (const std::exception&) {
        pass = true;
    }
    QVERIFY(pass == true);
}

void TestQtConfigUtils::testSetConfigurationReferenceUndefinedAgain()
{
    // set the same again (global_undefinedIap)
    QVERIFY(mEapConfigIf->setConfigurationReference(global_undefinedIap) == true);
}

void TestQtConfigUtils::testSetConfigurationReferenceFailure()
{
    // fails since referred IAP does not exist
    QVERIFY(mEapConfigIf->setConfigurationReference(global_invalidIap) == false);
    // change back to correct
    QVERIFY(mEapConfigIf->setConfigurationReference(global_undefinedIap) == true);
}

void TestQtConfigUtils::testCertificateAuthorityCertificates()
{
    mCaCertInfo = mEapConfigIf->certificateAuthorityCertificates();
    QVERIFY(mCaCertInfo.count() > 0);
}

void TestQtConfigUtils::testUserCertificates()
{
    mUserCertInfo = mEapConfigIf->userCertificates();
    QEXPECT_FAIL("", "No user certificates installed?", Continue);
    QVERIFY(mUserCertInfo.count() > 0);
}

void TestQtConfigUtils::testSupportedOuterTypes()
{
    QList<EapQtPluginInfo> plugins;
    plugins = mEapConfigIf->supportedOuterTypes();

    QVERIFY(plugins.count() > 0);

    QList<EapQtPluginHandle> handles;
    for (int i = 0; i < plugins.count(); i++) {
        handles.append(plugins[i].pluginHandle());
    }

    // check that handles contain outer types
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapAka) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginPeap) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapSim) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapTls) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapTtls) == true);

    // and no inner types
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapGtc) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapMschapv2) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginPap) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginPlainMschapv2) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginUndefined) == false);
}

void TestQtConfigUtils::testSupportedInnerTypesPeap()
{
    QList<EapQtPluginInfo> plugins;
    plugins = mEapConfigIf->supportedInnerTypes(EapQtPluginHandle::PluginPeap);

    QVERIFY(plugins.count() > 0);

    QList<EapQtPluginHandle> handles;
    for (int i = 0; i < plugins.count(); i++) {
        handles.append(plugins[i].pluginHandle());
    }

    // check that handles contain correct types
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapAka) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapGtc) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapMschapv2) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapSim) == true);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapTls) == true);

    // and other types
    QVERIFY(handles.contains(EapQtPluginHandle::PluginUndefined) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginPeap) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginEapTtls) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginPap) == false);
    QVERIFY(handles.contains(EapQtPluginHandle::PluginPlainMschapv2) == false);
}

void TestQtConfigUtils::testIsSupportedOuterTypePeap()
{
    QVERIFY(mEapConfigIf->isSupportedOuterType(EapQtPluginHandle::PluginPeap) == true);
}

void TestQtConfigUtils::testIsSupportedInnerTypePeap()
{
    QVERIFY(mEapConfigIf->isSupportedInnerType(EapQtPluginHandle::PluginPeap,
            EapQtPluginHandle::PluginPeap) == false);
    QVERIFY(mEapConfigIf->isSupportedInnerType(EapQtPluginHandle::PluginPeap,
            EapQtPluginHandle::PluginEapGtc) == true);
}

void TestQtConfigUtils::testSetConfigurationReferenceValidWlanIap()
{
    QVERIFY(mEapConfigIf->setConfigurationReference(global_wlanIap) == true);
}

void TestQtConfigUtils::testTestAgainForValidWlanIap()
{
    testCertificateAuthorityCertificates();
    testUserCertificates();
    testSupportedOuterTypes();
    testSupportedInnerTypesPeap();
    testIsSupportedOuterTypePeap();
    testIsSupportedInnerTypePeap();
}

void TestQtConfigUtils::testSelectedOuterTypes()
{
    QList<EapQtPluginHandle> outers;
    outers = mEapConfigIf->selectedOuterTypes();

    QVERIFY(outers.count() == 0);

    outers.clear();
    outers.append(EapQtPluginHandle::PluginPeap);
    outers.append(EapQtPluginHandle::PluginEapTls);
    // this must not be set when reading again
    outers.append(EapQtPluginHandle::PluginEapGtc);

    QVERIFY(mEapConfigIf->setSelectedOuterTypes(outers) == true);

    outers.clear();
    outers = mEapConfigIf->selectedOuterTypes();

    QVERIFY(outers.count() == 2);

    QVERIFY(outers.contains(EapQtPluginHandle::PluginPeap) == true);
    QVERIFY(outers.contains(EapQtPluginHandle::PluginEapTls) == true);
    QVERIFY(outers.contains(EapQtPluginHandle::PluginEapGtc) == false);
}

void TestQtConfigUtils::testIsSupportedTypeNewInstance()
{
    EapQtConfigInterface localEapConfigIf1(EapQtConfigInterface::EapBearerTypeWlan, global_wlanIap);
    QVERIFY(localEapConfigIf1.isSupportedOuterType(EapQtPluginHandle::PluginEapAka) == true);
    QVERIFY(localEapConfigIf1.isSupportedInnerType(EapQtPluginHandle::PluginEapTtls, EapQtPluginHandle::PluginEapAka) == true);

    EapQtConfigInterface localEapConfigIf2(EapQtConfigInterface::EapBearerTypeWlan, global_wlanIap);
    QVERIFY(localEapConfigIf2.isSupportedInnerType(EapQtPluginHandle::PluginPeap, EapQtPluginHandle::PluginEapMschapv2) == true);
    QVERIFY(localEapConfigIf2.isSupportedOuterType(EapQtPluginHandle::PluginEapMschapv2) == false);
}

void TestQtConfigUtils::testSaveConfigurationFull()
{
    int i = 0;

    QString peap_user("testuser");
    QString peap_pwd("testpwd");
    QString peap_realm("testrealm.org");
    QString peap_pacref("testpacgroupreference");
    uint peap_validity_time(15);

    QList<uint> peap_ciphers;
    peap_ciphers.append(0x0004);
    peap_ciphers.append(0x002F);
    peap_ciphers.append(0x0033);
    peap_ciphers.append(0x0034);

    QString peap_subject("Test PEAP subject");
    QString peap_issuer("Test PEAP subject");
    QString peap_serialnum("Test PEAP subject");
    QString peap_label("Test PEAP label");
    QString peap_thumbprint("Test PEAP subject");
    QByteArray peap_subjectkey =
        mCaCertInfo[0].value(EapQtCertificateInfo::SubjectKeyId).toByteArray();

    EapQtCertificateInfo peap_ca_cert;
    peap_ca_cert.setValue(EapQtCertificateInfo::SubjectName, peap_subject);
    peap_ca_cert.setValue(EapQtCertificateInfo::IssuerName, peap_issuer);
    peap_ca_cert.setValue(EapQtCertificateInfo::SerialNumber, peap_serialnum);
    peap_ca_cert.setValue(EapQtCertificateInfo::SubjectKeyId, peap_subjectkey);
    peap_ca_cert.setValue(EapQtCertificateInfo::ThumbPrint, peap_thumbprint);
    peap_ca_cert.setValue(EapQtCertificateInfo::CertificateLabel, peap_label);

    QString peap_subject_user("Test PEAP user subject");
    QString peap_issuer_user("Test PEAP user subject");
    QString peap_serialnum_user("Test PEAP user subject");
    QString peap_label_user("Test PEAP user label");
    QString peap_thumbprint_user("Test PEAP user subject");
    QByteArray peap_subjectkey_user =
        mCaCertInfo[1].value(EapQtCertificateInfo::SubjectKeyId).toByteArray();

    EapQtCertificateInfo peap_user_cert;
    peap_user_cert.setValue(EapQtCertificateInfo::SubjectName, peap_subject_user);
    peap_user_cert.setValue(EapQtCertificateInfo::IssuerName, peap_issuer_user);
    peap_user_cert.setValue(EapQtCertificateInfo::SerialNumber, peap_serialnum_user);
    peap_user_cert.setValue(EapQtCertificateInfo::SubjectKeyId, peap_subjectkey_user);
    peap_user_cert.setValue(EapQtCertificateInfo::ThumbPrint, peap_thumbprint_user);
    peap_user_cert.setValue(EapQtCertificateInfo::CertificateLabel, peap_label_user);

    EapQtPluginHandle handle_peap(EapQtPluginHandle::PluginPeap);
    EapQtPluginHandle handle_gtc(EapQtPluginHandle::PluginEapGtc);
    EapQtPluginHandle handle_mschap(EapQtPluginHandle::PluginEapMschapv2);
    EapQtPluginHandle handle_undef(EapQtPluginHandle::PluginUndefined);

    // **** config outer type (PEAP)
    EapQtConfig peap_config;
    peap_config.setValue(EapQtConfig::UsernameAutomatic, true);
    peap_config.setValue(EapQtConfig::Username, peap_user);
    peap_config.setValue(EapQtConfig::PasswordPrompt, true);
    peap_config.setValue(EapQtConfig::Password, peap_pwd);
    peap_config.setValue(EapQtConfig::PasswordStored, false);
    peap_config.setValue(EapQtConfig::RealmAutomatic, true);
    peap_config.setValue(EapQtConfig::Realm, peap_realm);
    peap_config.setValue(EapQtConfig::UsePseudonyms, true);
    peap_config.setValue(EapQtConfig::VerifyServerRealm, true);
    peap_config.setValue(EapQtConfig::SessionValidityTime, peap_validity_time);
    peap_config.setValue(EapQtConfig::PeapVersion0Allowed, true);
    peap_config.setValue(EapQtConfig::PeapVersion1Allowed, true);
    peap_config.setValue(EapQtConfig::PeapVersion2Allowed, true);
    peap_config.setValue(EapQtConfig::ProvisioningModeAuthenticated, true);
    peap_config.setValue(EapQtConfig::ProvisioningModeUnauthenticated, true);
    peap_config.setValue(EapQtConfig::PACGroupReference, peap_pacref);
    peap_config.setValue(EapQtConfig::WarnADHPNoPAC, true);
    peap_config.setValue(EapQtConfig::WarnADHPNoMatchingPAC, true);
    peap_config.setValue(EapQtConfig::WarnNotDefaultServer, true);
    peap_config.setValue(EapQtConfig::UseIdentityPrivacy, true);
    peap_config.setValue(EapQtConfig::AuthorityCertificateAutomatic, true);
    peap_config.setValue(EapQtConfig::ClientAuthenticationRequired, true);

    QList<QVariant> varList;
    for (i = 0; i < peap_ciphers.count(); i++) {
        varList.append(peap_ciphers[i]);
    }
    peap_config.setValue(EapQtConfig::CipherSuites, varList);
    varList.clear();

    varList.append(qVariantFromValue(peap_ca_cert));
    peap_config.setValue(EapQtConfig::AuthorityCertificate, varList);
    varList.clear();

    varList.append(qVariantFromValue(peap_user_cert));
    peap_config.setValue(EapQtConfig::UserCertificate, varList);
    varList.clear();

    // activate inner types (EAP-GTC & EAP-MSCHAPv2)
    varList.append(qVariantFromValue(handle_gtc));
    varList.append(qVariantFromValue(handle_mschap));
    peap_config.setValue(EapQtConfig::InnerType, varList);

    // OuterType is unset, i.e. QVariant::Invalid

    bool ok(false);
    ok = mEapConfigIf->saveConfiguration(handle_peap, peap_config);
    QVERIFY(ok);

    // *** config gtc
    QString gtc_user("testgtcuser");
    QString gtc_pwd("testgtcpwd");

    EapQtConfig gtc_config;

    gtc_config.setValue(EapQtConfig::Username, gtc_user);
    gtc_config.setValue(EapQtConfig::PasswordPrompt, true);
    gtc_config.setValue(EapQtConfig::Password, gtc_pwd);
    gtc_config.setValue(EapQtConfig::PasswordStored, false);
    gtc_config.setValue(EapQtConfig::OuterType, qVariantFromValue(handle_peap));

    // InnerType is unset, i.e. QVariant::Invalid

    ok = mEapConfigIf->saveConfiguration(handle_gtc, gtc_config);
    QVERIFY(ok);

    // *** config mschapv2
    QString mschap_user("testmschapuser");
    QString mschap_pwd("testmschappwd");

    EapQtConfig mschap_config;
    mschap_config.setValue(EapQtConfig::Username, mschap_user);
    mschap_config.setValue(EapQtConfig::PasswordPrompt, false);
    mschap_config.setValue(EapQtConfig::Password, mschap_pwd);
    mschap_config.setValue(EapQtConfig::PasswordStored, false);
    mschap_config.setValue(EapQtConfig::OuterType, qVariantFromValue(handle_peap));

    // InnerType is unset, i.e. QVariant::Invalid

    ok = mEapConfigIf->saveConfiguration(handle_mschap, mschap_config);
    QVERIFY(ok);

    // *****************************************
    // read back the values to check correctness
    // *****************************************

    // *** gtc
    EapQtPluginHandle read_handle;
    EapQtConfig read_config;
    ok = mEapConfigIf->readConfiguration(handle_peap, handle_gtc, read_config);
    QVERIFY(ok);

    QVERIFY(false == read_config.value(EapQtConfig::UsernameAutomatic).toBool());
    QVERIFY(gtc_config.value(EapQtConfig::Username) == read_config.value(EapQtConfig::Username));
    QVERIFY(gtc_config.value(EapQtConfig::PasswordPrompt) == read_config.value(EapQtConfig::PasswordPrompt));
    QVERIFY(true == read_config.value(EapQtConfig::PasswordStored).toBool());

    QVariant tmp = read_config.value(EapQtConfig::OuterType);
    read_handle = tmp.value<EapQtPluginHandle> ();
    QVERIFY(handle_peap == read_handle);

    // *** mschap
    read_config.clear();

    ok = mEapConfigIf->readConfiguration(handle_peap, handle_mschap, read_config);
    QVERIFY(ok);

    QVERIFY(false == read_config.value(EapQtConfig::UsernameAutomatic).toBool());
    QVERIFY(mschap_config.value(EapQtConfig::Username) == read_config.value(EapQtConfig::Username));
    QVERIFY(mschap_config.value(EapQtConfig::PasswordPrompt) == read_config.value(EapQtConfig::PasswordPrompt));
    QVERIFY(true == read_config.value(EapQtConfig::PasswordStored).toBool());

    tmp = read_config.value(EapQtConfig::OuterType);
    read_handle = tmp.value<EapQtPluginHandle> ();
    QVERIFY(handle_peap == read_handle);

    // *** PEAP
    read_config.clear();

    ok = mEapConfigIf->readConfiguration(handle_undef, handle_peap, read_config);
    QVERIFY(ok);

    // check only the valid PEAP parameters
    QVERIFY(peap_config.value(EapQtConfig::UsernameAutomatic) == read_config.value(EapQtConfig::UsernameAutomatic));
    QVERIFY(peap_config.value(EapQtConfig::Username) == read_config.value(EapQtConfig::Username));
    QVERIFY(peap_config.value(EapQtConfig::RealmAutomatic) == read_config.value(EapQtConfig::RealmAutomatic));
    QVERIFY(peap_config.value(EapQtConfig::Realm) == read_config.value(EapQtConfig::Realm));
    QVERIFY(peap_config.value(EapQtConfig::VerifyServerRealm) == read_config.value(EapQtConfig::VerifyServerRealm));
    QVERIFY(peap_config.value(EapQtConfig::SessionValidityTime) == read_config.value(EapQtConfig::SessionValidityTime));
    QVERIFY(peap_config.value(EapQtConfig::PeapVersion0Allowed) == read_config.value(EapQtConfig::PeapVersion0Allowed));
    QVERIFY(peap_config.value(EapQtConfig::PeapVersion1Allowed) == read_config.value(EapQtConfig::PeapVersion1Allowed));
    QVERIFY(peap_config.value(EapQtConfig::PeapVersion2Allowed) == read_config.value(EapQtConfig::PeapVersion2Allowed));
    QVERIFY(peap_config.value(EapQtConfig::UseIdentityPrivacy) == read_config.value(EapQtConfig::UseIdentityPrivacy));
    QVERIFY(peap_config.value(EapQtConfig::AuthorityCertificateAutomatic) == read_config.value(EapQtConfig::AuthorityCertificateAutomatic));
    QVERIFY(peap_config.value(EapQtConfig::ClientAuthenticationRequired) == read_config.value(EapQtConfig::ClientAuthenticationRequired));
    QVERIFY(peap_config.value(EapQtConfig::OuterType) == QVariant::Invalid);

    // ciphers
    QList<QVariant> varListWrite = peap_config.value(EapQtConfig::CipherSuites).toList();
    QList<QVariant> varListRead = read_config.value(EapQtConfig::CipherSuites).toList();

    QVERIFY(varListRead.count() == varListWrite.count());

    for (i = 0; i < peap_ciphers.count(); i++) {
        QVERIFY(varListRead.contains(varListWrite[i]) == true);
    }

    //  ca cert
    varListWrite = peap_config.value(EapQtConfig::AuthorityCertificate).toList();
    varListRead = read_config.value(EapQtConfig::AuthorityCertificate).toList();

    QVERIFY(varListRead.count() == varListWrite.count() == 1);

    QVERIFY(peap_ca_cert.value(EapQtCertificateInfo::SubjectName) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::SubjectName));
    QVERIFY(peap_ca_cert.value(EapQtCertificateInfo::SerialNumber) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::SerialNumber));
    QVERIFY(peap_ca_cert.value(EapQtCertificateInfo::SubjectKeyId) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::SubjectKeyId));
    QVERIFY(peap_ca_cert.value(EapQtCertificateInfo::ThumbPrint) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::ThumbPrint));
    // label is not stored, hence invalid in read
    QVERIFY(QVariant::Invalid == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::CertificateLabel));

    //  user cert
    varListWrite = peap_config.value(EapQtConfig::UserCertificate).toList();
    varListRead = read_config.value(EapQtConfig::UserCertificate).toList();

    QVERIFY(varListRead.count() == varListWrite.count() == 1);

    QVERIFY(peap_user_cert.value(EapQtCertificateInfo::SubjectName) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::SubjectName));
    QVERIFY(peap_user_cert.value(EapQtCertificateInfo::SerialNumber) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::SerialNumber));
    QVERIFY(peap_user_cert.value(EapQtCertificateInfo::SubjectKeyId) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::SubjectKeyId));
    QVERIFY(peap_user_cert.value(EapQtCertificateInfo::ThumbPrint) == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::ThumbPrint));
    // label is not stored, hence invalid in read
    QVERIFY(QVariant::Invalid == (varListRead[0].value<EapQtCertificateInfo>()).value(EapQtCertificateInfo::CertificateLabel));

    // inner types
    varListWrite = peap_config.value(EapQtConfig::InnerType).toList();
    varListRead = read_config.value(EapQtConfig::InnerType).toList();
    QVERIFY(varListRead.count() == varListWrite.count() == 2);

    QList<EapQtPluginHandle> read_handle_list;
    read_handle_list.append(varListRead[0].value<EapQtPluginHandle> ());
    read_handle_list.append(varListRead[1].value<EapQtPluginHandle> ());

    QVERIFY(read_handle_list.contains(handle_mschap) && read_handle_list.contains(handle_gtc));
}

void TestQtConfigUtils::testSaveConfigurationEapTtls()
{
    // EAP-TTLS/MSCHAPv2
}
#endif

void TestQtConfigUtils::testUiInstance()
{
#ifdef INCLUDE_UI_CASES

    QVERIFY(mEapConfigIf->setConfigurationReference(global_wlanIap) == true);

    // make sure there is a stored state in mEapConfigIf (EAP IF plugins loaded)
    mEapConfigIf->isSupportedInnerType(EapQtPluginHandle::PluginPeap,
            EapQtPluginHandle::PluginPeap) == false;
    mEapConfigIf->isSupportedInnerType(EapQtPluginHandle::PluginPeap,
            EapQtPluginHandle::PluginEapGtc) == true;

    QScopedPointer<CpBaseSettingView> ui(NULL);

    qDebug("creating AKA UI");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginUndefined, EapQtPluginHandle::PluginEapAka));
    qDebug("AKA UI created");
    QVERIFY(!ui.isNull());

    qDebug("creating SIM UI");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginUndefined, EapQtPluginHandle::PluginEapSim));
    qDebug("SIM UI created");
    QVERIFY(!ui.isNull());

    qDebug("creating LEAP UI");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginUndefined, EapQtPluginHandle::PluginLeap));
    qDebug("LEAP UI created");
    QVERIFY(!ui.isNull());

    qDebug("creating 1");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginUndefined, EapQtPluginHandle::PluginUndefined));
    qDebug("created 1");
    QVERIFY(ui.isNull());

    qDebug("creating 2");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginEapAka, EapQtPluginHandle::PluginEapSim));
    qDebug("created 2");
    QVERIFY(ui.isNull());

    qDebug("creating 3");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginEapSim, EapQtPluginHandle::PluginEapAka));
    qDebug("created 3");
    QVERIFY(ui.isNull());

    qDebug("creating 4");
    ui.reset(mEapConfigIf->uiInstance(EapQtPluginHandle::PluginEapAka, EapQtPluginHandle::PluginEapAka));
    qDebug("created 4");
    QVERIFY(ui.isNull());

#else
    QWARN("UI cases not included");
#endif
}

// Create main function using QTest marco.
QTEST_MAIN( TestQtConfigUtils)
