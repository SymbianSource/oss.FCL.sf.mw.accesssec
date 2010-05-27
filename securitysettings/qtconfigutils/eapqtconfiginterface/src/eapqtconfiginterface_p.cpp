/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of the License "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description: 
 *   EAP method configuration QT interface
 *
 */

/*
 * %version: 41 %
 */

#include <QDir>
#include <QList>
#include <QVariant>
#include <QPluginLoader>
#include <HbTranslator>
#include <QLocale>
#include <QCoreApplication>
#include <QDebug>

#include <cmmanager.h>
#include <cmpluginwlandef.h>
#include <EapGeneralSettings.h>

#include <eapqtplugininfo.h>
#include <eapqtcertificateinfo.h>

#include "cpeapplugininterface.h"
#include "eapqtconfiginterface_p.h"

// validators
#include "eapqtvalidatorpassword.h"
#include "eapqtvalidatorusername.h"
#include "eapqtvalidatorrealm.h"

static const QString eapPluginDir("\\resource\\qt\\plugins\\controlpanel\\eapsecurity");
static const QString eapTranslationFile("cpeapuiplugins");

EapQtConfigInterfacePrivate::EapQtConfigInterfacePrivate() :
  mValidatorInstance(true),
  mLastOuterHandle(EapQtPluginHandle::PluginUndefined),
  mTranslator(NULL),
  mEapGsIf(NULL), 
  mEapTypeIf(NULL),
  mIapId(0),
  mEapBearer(ELan),
  mEapDbIndex(EapQtConfigInterface::IapIdUndefined),
  mEapDbIndexValid(false)
{
    qDebug("EapQtConfigInterfacePrivate() - created validator instance, this = 0x%08x", this);

}

EapQtConfigInterfacePrivate::EapQtConfigInterfacePrivate(/* EapQtConfigInterface *configIf, */
    const EapQtConfigInterface::EapBearerType bearerType, const int iapId) :  
  mValidatorInstance(false),
  mLastOuterHandle(EapQtPluginHandle::PluginUndefined),
  mTranslator(NULL), 
  mEapGsIf(NULL), 
  mEapTypeIf(NULL),
  mIapId(iapId),
  mEapBearer(ELan),
  mEapDbIndex(EapQtConfigInterface::IapIdUndefined),
  mEapDbIndexValid(false)
{
    qDebug("EapQtConfigInterfacePrivate() - creating non-validator instance, this = 0x%08x", this);


    switch (bearerType) {
    case EapQtConfigInterface::EapBearerTypeVpn:
        mEapBearer = EVpn;
        break;
    default:
        // All others default to EapQtConfigInterface::EapBearerTypeWlan i.e. ELan
        mEapBearer = ELan;
    }

    if (!setEapDbIndex(iapId)) {
        qDebug("ERROR: EapQtConfigInterfacePrivate() - setIapId failed, bearer = %d, index = %d",
            mEapBearer, iapId);
        shutdown();
        // throw an exception
        qt_symbian_throwIfError(KErrNotFound);
    }

    // load plugins after everything else is ok
    qDebug("EapQtConfigInterfacePrivate() - load plugins");
    loadPlugins();

    qDebug("EapQtConfigInterfacePrivate() - ends");
}

EapQtConfigInterfacePrivate::~EapQtConfigInterfacePrivate()
{
    qDebug("EapQtConfigInterfacePrivate::~EapQtConfigInterfacePrivate(), this = 0x%08x", this);

    shutdown();
}

void EapQtConfigInterfacePrivate::shutdown()
{
    qDebug("EapQtConfigInterfacePrivate::shutdown(), this = 0x%08x", this);


    mOuterEapsOn.Close();
    mOuterEapsOff.Close();

    // cleanup Ecom
    REComSession::FinalClose();

    // mTranslator gets deleted automatically (QScopedPointer)
    // mEapTypeIf gets deleted automatically (QScopedPointer)
    // mEapGsIf gets deleted automatically (QScopedPointer)
}

bool EapQtConfigInterfacePrivate::setConfigurationReference(const int iapId)
{
    qDebug("EapQtConfigInterfacePrivate::setConfigurationReference - requested id: %d, this = 0x%08x", iapId, this);

    checkInstanceThrowing();
    return setEapDbIndex(iapId);
}

bool EapQtConfigInterfacePrivate::setEapDbIndex(const int iapId)
{

    qDebug("EapQtConfigInterfacePrivate::setIapId - requested id: %d, this = 0x%08x", iapId, this);


    // optimization: do not re-create the interface if the reference does
    // not change and mEapGsIf exists already

    // WLAN reference is checked after setEapWlanDbIndex below since iapId may be
    // different than WLAN service ID

    // case for EapQtConfigInterface::IapIdUndefined i.e. setIapId was called
    // with a negative id last time and now again
    if (!mEapDbIndexValid && !mEapGsIf.isNull() && iapId < 0) {
        qDebug(
            "EapQtConfigInterfacePrivate::setIapId - interface created for IapIdUndefined already");
        return true;
    }

    // case for VPN (or any other bearer) in which iap id equals EAP db index
    if (mEapBearer != ELan && mEapDbIndexValid && !mEapGsIf.isNull() && iapId == mEapDbIndex) {
        qDebug(
            "EapQtConfigInterfacePrivate::setIapId - interface created for requested IAP ID for VPN already");
        return true;
    }

    // save the current id for checking if WLAN reference changes or not
    TInt previousEapDbIndex = mEapDbIndex;
    bool wlanIndexOk = true;

    // allow accessing certain methods with negative iapId
    if (iapId < 0) {
        // set to zero to be able to create EAP server instances
        mEapDbIndex = 0;
        mEapDbIndexValid = false;
    }
    // for real usage iapId must not be negative
    else {
        // for VPN
        mIapId = iapId;
        mEapDbIndex = iapId;
        mEapDbIndexValid = true;

        // for WLAN
        if (mEapBearer == ELan) {
            // get WLAN service ID as the reference
            mEapDbIndexValid = setEapWlanDbIndex(iapId);
            wlanIndexOk = mEapDbIndexValid;
            // do not re-create if the interface is ok for the new (i.e. same) index already
            if (!mEapGsIf.isNull() && mEapDbIndex == previousEapDbIndex) {
                qDebug() << "EapQtConfigInterfacePrivate::setIapId - interface"
                    << "created for requested IAP ID for WLAN already";
                return true;
            }

        }
    }

    // delete possibly existing instances
    mEapGsIf.reset(NULL);
    mEapTypeIf.reset(NULL);

    mCurrentServerEapType = *EapExpandedTypeNone.GetType();
    mLastOuterHandle = EapQtPluginHandle::PluginUndefined;

    if (!wlanIndexOk && mEapBearer == ELan) {
        // setEapWlanDbIndex was called and failed
        qDebug("ERROR: EapQtConfigInterfacePrivate::setIapId() - setEapWlanDbIndex failed");
        return false;
    }

    qDebug(
        "EapQtConfigInterfacePrivate::setIapId() - calls CEapGeneralSettings::NewL(), bearer = %d, index = %d",
        mEapBearer, mEapDbIndex);

    // load EAP general settings interface
    CEapGeneralSettings* tmp = NULL;
    TRAPD(err, tmp = CEapGeneralSettings::NewL(mEapBearer, mEapDbIndex));
    if (err != KErrNone) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::setIapId - CEapGeneralSettings::NewL() failed");
        mEapDbIndexValid = false;
        return false;
    }

    // set to the created instance
    mEapGsIf.reset(tmp);

    return true;
}

bool EapQtConfigInterfacePrivate::setEapWlanDbIndex(const int iapId)
{
    qDebug("EapQtConfigInterfacePrivate::setEapWlanDbIndex - requested id: %d, this = 0x%08x", iapId, this);


    RCmManager cmm;
    TRAPD(err, cmm.OpenL());
    if (err != KErrNone) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::setEapWlanDbIndex - cmm.OpenL() failed",
            mEapBearer, iapId);
        mEapDbIndex = EapQtConfigInterface::IapIdUndefined;
        mIapId = 0;
        return false;
    }

    TRAP(err, mEapDbIndex = cmm.GetConnectionMethodInfoIntL(iapId, CMManager::EWlanServiceId));
    if (err != KErrNone) {
        qDebug(
            "ERROR: EapQtConfigInterfacePrivate::setEapWlanDbIndex - cmm.GetConnectionMethodInfoIntL() failed",
            mEapBearer, iapId);
        cmm.Close();
        mEapDbIndex = EapQtConfigInterface::IapIdUndefined;
        mIapId = 0;
        return false;
    }

    cmm.Close();

    qDebug("EapQtConfigInterfacePrivate::setEapWlanDbIndex - obtained WLAN service id: %d",
        mEapDbIndex);

    return true;
}

void EapQtConfigInterfacePrivate::checkInstanceThrowing() const
{
    qDebug() << "EapQtConfigInterfacePrivate::checkInstanceThrowing() - mValidatorInstance:"
        << mValidatorInstance;

    if (mValidatorInstance) {
        qDebug(
            "ERROR: EapQtConfigInterfacePrivate::checkInstanceThrowing - method not supported by this instance");
        qt_symbian_throwIfError(KErrNotSupported);
    }
}

void EapQtConfigInterfacePrivate::appendEapTypes(const RArray<TEapExpandedType>* const eapTypes,
    QList<QByteArray>* const eapList)
{
    qDebug("EapQtConfigInterfacePrivate::appendEapTypes(), this = 0x%08x", this);


    Q_ASSERT(eapTypes);
    Q_ASSERT(eapList);

    qDebug("EapQtConfigInterfacePrivate - appendEapTypes, EAP count = %d", eapTypes->Count());

    QByteArray tmpEap;
    for (int ind = 0; ind < eapTypes->Count(); ind++) {
        tmpEap.append(reinterpret_cast<const char*> ((*eapTypes)[ind].GetValue().Ptr()),
            (*eapTypes)[ind].GetValue().Length());
        eapList->append(tmpEap);
        qDebug() << "EapQtConfigInterfacePrivate - appendEapTypes added EAP: " << tmpEap.toHex();
        tmpEap.clear();
    }
}

QList<EapQtPluginInfo> EapQtConfigInterfacePrivate::supportedOuterTypes()
{
    qDebug("EapQtConfigInterfacePrivate::supportedOuterTypes(), this = 0x%08x", this);


    checkInstanceThrowing();

    if (mEapGsIf.isNull()) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::supportedOuterTypes() - mEapGsIf is NULL");
        mOuterEapsOn.Reset();
        mOuterEapsOff.Reset();
        // return empty list
        mSupportedOuterTypes.clear();
        return mSupportedOuterTypes;
    }

    // get outer EAPs from EAP server,
    // returned in two lists: enabled and disabled outer EAPs
    // do this always as the list might have changed and mOuterEapsOn/Off are needed in
    // other methods

    mOuterEapsOn.Reset();
    mOuterEapsOff.Reset();

    qDebug("EapQtConfigInterfacePrivate::supportedOuterTypes() - calls GetEapMethods()");

    TUint err = mEapGsIf->GetEapMethods(mOuterEapsOn, mOuterEapsOff);
    if (err != KErrNone) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::supportedOuterTypes() - GetEapMethods failed");
        mOuterEapsOn.Reset();
        mOuterEapsOff.Reset();
        // return empty list
        mSupportedOuterTypes.clear();
        return mSupportedOuterTypes;
    }

    // optimization: collect the list only once per instance life time
    // since no new EAPs will appear to the combination of mOuterEapsOn and mOuterEapsOff
    if (mSupportedOuterTypes.count() > 0) {
        qDebug(
            "EapQtConfigInterfacePrivate - supportedOuterTypes: supported EAPs already listed, return stored list");
        return mSupportedOuterTypes;
    }

    qDebug("EapQtConfigInterfacePrivate - supportedOuterTypes: copy response to QList");

    // copy response to qlist for easier comparison
    QList<QByteArray> outerEaps;

    appendEapTypes(&mOuterEapsOn, &outerEaps);
    appendEapTypes(&mOuterEapsOff, &outerEaps);

    qDebug("EapQtConfigInterfacePrivate - supportedOuterTypes: EAP server outer type count: %d",
        outerEaps.count());

    qDebug("EapQtConfigInterfacePrivate - supportedOuterTypes: collected UI plugin count: %d",
        mPluginInfos.count());

    // set mSupportedOuterTypes to contain only EAPs that both UI and EAP server support
    QByteArray tmpEap;
    for (int ind = 0; ind < mPluginInfos.count(); ind++) {
        tmpEap = mPluginInfos[ind].pluginHandle().type().eapExpandedData();
        if (outerEaps.contains(tmpEap)) {
            mSupportedOuterTypes.append(mPluginInfos[ind]);
            qDebug() << "EapQtConfigInterfacePrivate - supportedOuterTypes: appended EAP: "
                << tmpEap.toHex();
        }
    }

    qDebug("EapQtConfigInterfacePrivate - supportedOuterTypes: supported EAP count: %d",
        mSupportedOuterTypes.count());

    return mSupportedOuterTypes;
}

// checks if UI plugins support supplied eapType and returns the
// index (in mPluginInfos) of the supporting plugin
bool EapQtConfigInterfacePrivate::isUiSupported(const QByteArray &eapType, int &pluginIndex) const
{
    qDebug("EapQtConfigInterfacePrivate::isUiSupported(), this = 0x%08x", this);

    bool ret = false;
    for (int ind = 0; ind < mPluginInfos.count(); ind++) {
        qDebug("EapQtConfigInterfacePrivate::isUiSupported() - checking index: %d", ind);
        pluginIndex = ind;
        if (eapType == mPluginInfos[ind].pluginHandle().type().eapExpandedData()) {
            qDebug("EapQtConfigInterfacePrivate::isUiSupported() - ui supported!");
            ret = true;
            break;
        }
    }
    return ret;
}

QList<EapQtPluginInfo> EapQtConfigInterfacePrivate::supportedInnerTypes(
    const EapQtPluginHandle& outer)
{
    qDebug("EapQtConfigInterfacePrivate::supportedInnerTypes(), this = 0x%08x", this);


    checkInstanceThrowing();

    // check if we already have up-to-date data
    if (mLastOuterHandle == outer) {
        return mSupportedInnerTypes;
    }

    // clear previous query result
    mSupportedInnerTypes.clear();
    mLastOuterHandle = EapQtPluginHandle::PluginUndefined;

    qDebug()
        << "EapQtConfigInterfacePrivate::supportedInnerTypes() - calls isSupportedOuterType for: "
        << outer.type().eapExpandedData().toHex();

    // check if the queried outer EAP is supported
    if (!isSupportedOuterType(outer)) {
        qDebug()
            << "ERROR: EapQtConfigInterfacePrivate::supportedInnerTypes() - queried outer type not supported: "
            << outer.type().eapExpandedData().toHex();
        // return empty list
        return mSupportedInnerTypes;
    }

    qDebug("EapQtConfigInterfacePrivate::supportedInnerTypes() - calls getEapTypeIf");

    // get outer EAP settings interface
    getEapTypeIf(outer);
    if (mEapTypeIf.isNull()) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::supportedInnerTypes() - getEapTypeIf failed");
        // return empty list
        return mSupportedInnerTypes;
    }

    // get outer EAP settings
    EAPSettings eapSettings;
    TRAPD(err, mEapTypeIf->GetConfigurationL(eapSettings));
    // getEapTypeIf has set mCurrentServerEapType correctly for comparison
    if (err != KErrNone || eapSettings.iEAPExpandedType != mCurrentServerEapType) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::supportedInnerTypes - GetConfigurationL failed");
        // clear the instance so that the next attempt starts from scratch
        mEapTypeIf.reset(NULL);
        // return empty list
        return mSupportedInnerTypes;
    }

    // store inner EAPs supported by EAP server
    QList<QByteArray> innerEaps;
    appendEapTypes(&(eapSettings.iEnabledEncapsulatedEAPExpandedTypes), &innerEaps);
    appendEapTypes(&(eapSettings.iDisabledEncapsulatedEAPExpandedTypes), &innerEaps);

    int pluginIndex = 0;
    for (int ind = 0; ind < innerEaps.count(); ind++) {
        // report only EAPs which do have an UI plugin
        if (isUiSupported(innerEaps[ind], pluginIndex)) {
            mSupportedInnerTypes.append(mPluginInfos[pluginIndex]);
            qDebug() << "EapQtConfigInterfacePrivate::supportedInnerTypes - added inner EAP: "
                << innerEaps[ind].toHex();
        }
    }

    mLastOuterHandle = outer;

    return mSupportedInnerTypes;
}

void EapQtConfigInterfacePrivate::copyCertificateInfo(
    const RPointerArray<EapCertificateEntry>* const certEntries,
    QList<EapQtCertificateInfo>* const certInfos)
{
    qDebug("EapQtConfigInterfacePrivate::copyCertificateInfo(), this = 0x%08x", this);


    Q_ASSERT(certEntries);
    Q_ASSERT(certInfos);

    certInfos->clear();

    EapQtCertificateInfo cert;
    TKeyIdentifier subjectKeyId;
    const TDes* text = 0;
    int ind = 0;

    for (ind = 0; ind < certEntries->Count(); ind++) {

        EapCertificateEntry* certPtr = (*certEntries)[ind];

        qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo *** certificate starts *** ";

        if (certPtr->GetSubjectNamePresent() != EFalse) {

            text = certPtr->GetSubjectName();
            cert.setValue(EapQtCertificateInfo::SubjectName, QString::fromUtf16(text->Ptr(),
                text->Length()));

            qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo SubjectName: "
                << QString::fromUtf16(text->Ptr(), text->Length());
        }
        if (certPtr->GetIssuerNamePresent() != EFalse) {

            text = certPtr->GetIssuerName();
            cert.setValue(EapQtCertificateInfo::IssuerName, QString::fromUtf16(text->Ptr(),
                text->Length()));

            qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo IssuerName: "
                << QString::fromUtf16(text->Ptr(), text->Length());
        }
        if (certPtr->GetSerialNumberPresent() != EFalse) {

            text = certPtr->GetSerialNumber();
            cert.setValue(EapQtCertificateInfo::SerialNumber, QString::fromUtf16(text->Ptr(),
                text->Length()));

            qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo SerialNumber: "
                << QString::fromUtf16(text->Ptr(), text->Length());
        }
        if (certPtr->GetSubjectKeyIdPresent() != EFalse) {

            subjectKeyId = certPtr->GetSubjectKeyId();
            cert.setValue(EapQtCertificateInfo::SubjectKeyId, QByteArray(
                reinterpret_cast<const char*> (subjectKeyId.Ptr()), subjectKeyId.Length()));

            qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo SubjectKeyId: "
                << (QByteArray(reinterpret_cast<const char*> (subjectKeyId.Ptr()),
                    subjectKeyId.Length())).toHex();
        }
        if (certPtr->GetThumbprintPresent() != EFalse) {

            text = certPtr->GetThumbprint();
            cert.setValue(EapQtCertificateInfo::ThumbPrint, QString::fromUtf16(text->Ptr(),
                text->Length()));

            qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo ThumbPrint: "
                << QString::fromUtf16(text->Ptr(), text->Length());
        }
        if (certPtr->GetLabelPresent() != EFalse) {

            text = certPtr->GetLabel();
            cert.setValue(EapQtCertificateInfo::CertificateLabel, QString::fromUtf16(text->Ptr(),
                text->Length()));

            qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo CertificateLabel: "
                << QString::fromUtf16(text->Ptr(), text->Length());
        }

        qDebug() << "EapQtConfigInterfacePrivate - copyCertificateInfo *** certificate ends *** ";

        certInfos->append(cert);

    }
}

bool EapQtConfigInterfacePrivate::fetchCertificates(QList<EapQtCertificateInfo>* const caInfos,
    QList<EapQtCertificateInfo>* const clientInfos)
{
    qDebug("EapQtConfigInterfacePrivate::fetchCertificates(), this = 0x%08x", this);


    Q_ASSERT(caInfos != NULL || clientInfos != NULL || !mEapGsIf.isNull());

    TInt err(KErrNone);
    RPointerArray<EapCertificateEntry> clientCerts;
    RPointerArray<EapCertificateEntry> caCerts;

    // lists are always queried again as the user might have installed new certificates
    // during the life time of the object
    err = mEapGsIf->GetCertificateLists(clientCerts, caCerts);
    if (err != KErrNone) {
        qDebug("EapQtConfigInterfacePrivate - fetchCertificates failed: %d", err);
        caCerts.ResetAndDestroy();
        clientCerts.ResetAndDestroy();
        return false;
    }

    qDebug("user cert count: %d, CA cert count: %d", clientCerts.Count(), caCerts.Count());

    if (caInfos != NULL) {
        copyCertificateInfo(&caCerts, caInfos);
    }
    if (clientInfos != NULL) {
        copyCertificateInfo(&clientCerts, clientInfos);
    }

    caCerts.ResetAndDestroy();
    clientCerts.ResetAndDestroy();
    return true;
}

QList<EapQtCertificateInfo> EapQtConfigInterfacePrivate::certificateAuthorityCertificates()
{
    qDebug("EapQtConfigInterfacePrivate::certificateAuthorityCertificates(), this = 0x%08x", this);


    checkInstanceThrowing();

    QList<EapQtCertificateInfo> list;
    if (!fetchCertificates(&list, 0)) {
        // query failed
        list.clear();
    }
    return list;
}

QList<EapQtCertificateInfo> EapQtConfigInterfacePrivate::userCertificates()
{
    qDebug("EapQtConfigInterfacePrivate::userCertificates(), this = 0x%08x", this);


    checkInstanceThrowing();

    QList<EapQtCertificateInfo> list;
    if (!fetchCertificates(0, &list)) {
        // query failed
        list.clear();
    }
    return list;
}

void EapQtConfigInterfacePrivate::getEapTypeIf(const EapQtPluginHandle& pluginHandle)
{
    qDebug("EapQtConfigInterfacePrivate::getEapTypeIf(), this = 0x%08x", this);


    // dig up the EAP type in TEapExpandedType format
    TEapExpandedType eapServerType;
    QByteArray eapType = pluginHandle.type().eapExpandedData();
    TInt err(KErrNone);

    qDebug() << "EapQtConfigInterfacePrivate - getEapTypeIf: wanted EAP type: " << eapType.toHex();

    // no need to check if this is successful,
    // CEapType::NewL call will handle errors
    (void) eapServerType.SetValue(eapType.data(), eapType.length());

    // slight optimization, load interface only if it does not exist or the EAP type changes
    if (mEapTypeIf.isNull() || mCurrentServerEapType != eapServerType) {

        qDebug("EapQtConfigInterfacePrivate - getEapTypeIf deletes previous instance");

        // delete previous instance
        mEapTypeIf.reset(NULL);
        mCurrentServerEapType = eapServerType;

        qDebug("EapQtConfigInterfacePrivate - getEapTypeIf calls CEapType::NewL()");

        // trap all leaves
        CEapType* tmp = NULL;
        TRAP(err, tmp = CEapType::NewL(mEapBearer, mEapDbIndex, mCurrentServerEapType));
        if (err != KErrNone) {
            qDebug(
                "ERROR: EapQtConfigInterfacePrivate - getEapTypeIf CEapType::NewL failed with error: %d",
                err);
            mCurrentServerEapType = *EapExpandedTypeNone.GetType();
        }
        mEapTypeIf.reset(tmp);
    }

    // always clear the tunnelling type state just in case some earlier call has set it
    if (!mEapTypeIf.isNull()) {
        mEapTypeIf->SetTunnelingType(*EapExpandedTypeNone.GetType());
    }

}

// in config:
// if OuterType is defined, the configuration for pluginHandle is set inside this OuterType
// if OuterType is not defined, pluginHandle is for an outer type
// if InnerType is defined, the defined inner types in config are activated for pluginHandle
// if InnerType is not defined, the pluginHandle does not activate any inner type (or they do not exist)
bool EapQtConfigInterfacePrivate::saveConfiguration(const EapQtPluginHandle& pluginHandle,
    EapQtConfig& config)
{
    qDebug("EapQtConfigInterfacePrivate::saveConfiguration(), this = 0x%08x", this);


    checkInstanceThrowing();

    if (!mEapDbIndexValid) {
        qDebug() << "ERROR: Database reference not valid, call setConfigurationReference first!";
        return false;
    }

    // only check if EAP ui is supported here,
    // getEapTypeIf checks the EAP server support
    int dummy = 0;
    if (!isUiSupported(pluginHandle.type().eapExpandedData(), dummy)) {
        qDebug(
            "ERROR: EapQtConfigInterfacePrivate::saveConfiguration() - UI not supported for the requested EAP");
        return false;
    }

    getEapTypeIf(pluginHandle);
    if (mEapTypeIf.isNull()) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::saveConfiguration() - getEapTypeIf failed");
        return false;
    }

    // set tunneling type
    // if we are configuring outer type, OuterType == Invalid or EapQtPluginHandle::PluginUndefined

    EapQtPluginHandle tmpOuterHandle;
    QVariant varValue = config.value(EapQtConfig::OuterType);
    if (varValue != QVariant::Invalid) {
        tmpOuterHandle = varValue.value<EapQtPluginHandle> ();
    }
    else {
        tmpOuterHandle = EapQtPluginHandle::PluginUndefined;
    }

    TEapExpandedType tmpOuterEap;
    tmpOuterEap.SetValue(tmpOuterHandle.type().eapExpandedData().data(),
        tmpOuterHandle.type().eapExpandedData().length());

    qDebug() << "EapQtConfigInterfacePrivate::saveConfiguration() - sets tunnelling type to: "
        << tmpOuterHandle.type().eapExpandedData().toHex();

    mEapTypeIf->SetTunnelingType(tmpOuterEap);

    // set EAP type here
    QByteArray eapType = pluginHandle.type().eapExpandedData();

    // copy config to EAP settings,
    // no need to check if this is successful,
    // SetConfigurationL call will handle errors
    EAPSettings eapSettings;
    (void) eapSettings.iEAPExpandedType.SetValue(eapType.data(), eapType.length());

    // copy the rest of the settings in the function
    copyToEapSettings(config, eapSettings);
    // store settings
    TRAPD(err, mEapTypeIf->SetConfigurationL(eapSettings));
    if (err != KErrNone) {
        qDebug("ERROR: EapQtConfigInterfacePrivate - saveConfiguration: SetConfigurationL failed");
        // clear the instance so that the next attempt starts from scratch
        mEapTypeIf.reset(NULL);
        mCurrentServerEapType = *EapExpandedTypeNone.GetType();
        return false;
    }

    return true;
}

// config must be empty when calling
bool EapQtConfigInterfacePrivate::readConfiguration(const EapQtPluginHandle& outerHandle,
    const EapQtPluginHandle& pluginHandle, EapQtConfig& config)
{
    qDebug("EapQtConfigInterfacePrivate::readConfiguration(), this = 0x%08x", this);

    // clear input
    config.clear();

    checkInstanceThrowing();

    if (!mEapDbIndexValid) {
        qDebug() << "ERROR: Database reference not valid, call setConfigurationReference first!";
        return false;
    }

    // only check if UI is supported for pluginHandle here,
    // getEapTypeIf checks the EAP server support
    int dummy = 0;
    if (!isUiSupported(pluginHandle.type().eapExpandedData(), dummy)) {
        qDebug(
            "ERROR: EapQtConfigInterfacePrivate::readConfiguration - UI not supported for the requested EAP");
        return false;
    }

    getEapTypeIf(pluginHandle);
    if (mEapTypeIf.isNull()) {
        qDebug("ERROR: EapQtConfigInterfacePrivate::readConfiguration - getEapTypeIf failed");
        return false;
    }

    // set tunneling type
    // if we are configuring outer type, outerHandle == EapQtPluginHandle::PluginUndefined
    // and calling SetTunnelingType is also ok
    TEapExpandedType tmpEap;
    tmpEap.SetValue(outerHandle.type().eapExpandedData().data(),
        outerHandle.type().eapExpandedData().length());

    qDebug() << "EapQtConfigInterfacePrivate::readConfiguration - sets tunnelling type to: "
        << outerHandle.type().eapExpandedData().toHex();

    mEapTypeIf->SetTunnelingType(tmpEap);

    // always set OuterType,
    // set to EapQtPluginHandle::PluginUndefined if no outer type specified
    config.setValue(EapQtConfig::OuterType, qVariantFromValue(outerHandle));

    qDebug("EapQtConfigInterfacePrivate::readConfiguration - calls GetConfigurationL()");

    // trap all leaves
    EAPSettings eapSettings;
    TRAPD(err, mEapTypeIf->GetConfigurationL(eapSettings));

    // check if failed or something strange happened (incorrect EAP type settings received)  
    if (err != KErrNone || eapSettings.iEAPExpandedType != mCurrentServerEapType) {
        qDebug("ERROR: EapQtConfigInterfacePrivate - readConfiguration: GetConfigurationL failed");
        // clear the instance so that the next attempt starts from scratch
        mEapTypeIf.reset(NULL);
        mCurrentServerEapType = *EapExpandedTypeNone.GetType();
        // nothing to be set to config
        return false;
    }
    copyFromEapSettings(eapSettings, config);
    return true;
}

bool EapQtConfigInterfacePrivate::convertToBool(TBool value)
{
    return (value != EFalse ? true : false);
}

TBool EapQtConfigInterfacePrivate::convertToTbool(bool value)
{
    return (value ? ETrue : EFalse);
}

void EapQtConfigInterfacePrivate::copyToEapSettings(EapQtConfig& config, EAPSettings& eapSettings)
{

    qDebug("EapQtConfigInterfacePrivate::copyToEapSettings(), this = 0x%08x", this);


    int ind = 0;

    QVariant varValue = config.value(EapQtConfig::UsernameAutomatic);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iUseAutomaticUsernamePresent = ETrue;
        eapSettings.iUseAutomaticUsername = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings UsernameAutomatic: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::AuthorityCertificateAutomatic);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iUseAutomaticCACertificatePresent = ETrue;
        eapSettings.iUseAutomaticCACertificate = convertToTbool(varValue.toBool());
        qDebug()
            << "EapQtConfigInterfacePrivate - copyToEapSettings AuthorityCertificateAutomatic: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::Username);
    // do not copy if too large string
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        // QString::utf16 returns a null terminated string
        eapSettings.iUsername.Copy(varValue.toString().utf16());
        eapSettings.iUsernamePresent = ETrue;
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings Username: "
            << varValue.toString();
    }

    varValue = config.value(EapQtConfig::PasswordPrompt);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iShowPassWordPromptPresent = ETrue;
        eapSettings.iShowPassWordPrompt = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings PasswordPrompt: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::Password);
    // do not copy if too large string
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        //QString::utf16 returns a null terminated string
        eapSettings.iPassword.Copy(varValue.toString().utf16());
        eapSettings.iPasswordPresent = ETrue;
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings Password: "
            << varValue.toString();
    }

    varValue = config.value(EapQtConfig::PasswordClear);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iPasswordExistPresent = ETrue;
        eapSettings.iPasswordExist = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings PasswordClear: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::RealmAutomatic);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iUseAutomaticRealmPresent = ETrue;
        eapSettings.iUseAutomaticRealm = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings RealmAutomatic: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::Realm);
    // do not copy if too large string
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        // QString::utf16 returns a null terminated string
        eapSettings.iRealm.Copy(varValue.toString().utf16());
        eapSettings.iRealmPresent = ETrue;
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings Realm: "
            << varValue.toString();
    }

    varValue = config.value(EapQtConfig::UsePseudonyms);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iUsePseudonymsPresent = ETrue;
        eapSettings.iUsePseudonyms = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings UsePseudonyms: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::VerifyServerRealm);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iVerifyServerRealmPresent = ETrue;
        eapSettings.iVerifyServerRealm = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings VerifyServerRealm: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::ClientAuthenticationRequired);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iRequireClientAuthenticationPresent = ETrue;
        eapSettings.iRequireClientAuthentication = convertToTbool(varValue.toBool());
        qDebug()
            << "EapQtConfigInterfacePrivate - copyToEapSettings ClientAuthenticationRequired: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::SessionValidityTime);
    if (varValue.type() == QVariant::UInt) {
        eapSettings.iSessionValidityTimePresent = ETrue;
        eapSettings.iSessionValidityTime = varValue.toUInt();
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings SessionValidityTime: "
            << varValue.toUInt();
    }

    varValue = config.value(EapQtConfig::PeapVersion0Allowed);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iPEAPVersionsPresent = ETrue;
        eapSettings.iPEAPv0Allowed = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings PeapVersion0Allowed: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::PeapVersion1Allowed);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iPEAPVersionsPresent = ETrue;
        eapSettings.iPEAPv1Allowed = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings PeapVersion1Allowed: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::PeapVersion2Allowed);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iPEAPVersionsPresent = ETrue;
        eapSettings.iPEAPv2Allowed = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings PeapVersion2Allowed: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::ProvisioningModeAuthenticated);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iAuthProvModeAllowedPresent = ETrue;
        eapSettings.iAuthProvModeAllowed = convertToTbool(varValue.toBool());
        qDebug()
            << "EapQtConfigInterfacePrivate - copyToEapSettings ProvisioningModeAuthenticated: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::ProvisioningModeUnauthenticated);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iUnauthProvModeAllowedPresent = ETrue;
        eapSettings.iUnauthProvModeAllowed = convertToTbool(varValue.toBool());
        qDebug()
            << "EapQtConfigInterfacePrivate - copyToEapSettings ProvisioningModeUnauthenticated: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::PACGroupReference);
    // do not copy if too large string
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        // not supported
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings PACGroupReference: "
            << varValue.toString();
    }

    varValue = config.value(EapQtConfig::WarnADHPNoPAC);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iWarnADHPNoPACPresent = ETrue;
        eapSettings.iWarnADHPNoPAC = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings WarnADHPNoPAC: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::WarnADHPNoMatchingPAC);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iWarnADHPNoMatchingPACPresent = ETrue;
        eapSettings.iWarnADHPNoMatchingPAC = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings WarnADHPNoMatchingPAC: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::WarnNotDefaultServer);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iWarnNotDefaultServerPresent = ETrue;
        eapSettings.iWarnNotDefaultServer = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings WarnNotDefaultServer: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::UseIdentityPrivacy);
    if (varValue.type() == QVariant::Bool) {
        eapSettings.iUseIdentityPrivacyPresent = ETrue;
        eapSettings.iUseIdentityPrivacy = convertToTbool(varValue.toBool());
        qDebug() << "EapQtConfigInterfacePrivate - copyToEapSettings UseIdentityPrivacy: "
            << varValue.toBool();
    }

    varValue = config.value(EapQtConfig::InnerType);
    if (varValue.type() == QVariant::List) {

        // not need to set disable inner types
        // EAP server takes care of them internally

        qDebug() << "EapQtConfigInterfacePrivate::copyToEapSettings() - InnerType present";

        QList<QVariant> varList = varValue.toList();
        TEapExpandedType tmpEap;
        EapQtPluginHandle tmpHandle;

        for (ind = 0; ind < varList.count(); ind++) {
            if (varList[ind].canConvert<EapQtPluginHandle> ()) {
                // set to true only if at least one item is ok
                eapSettings.iEnabledEncapsulatedEAPExpandedTypesPresent = ETrue;

                tmpHandle = varList[ind].value<EapQtPluginHandle> ();
                tmpEap.SetValue(tmpHandle.type().eapExpandedData().data(),
                    tmpHandle.type().eapExpandedData().length());
                eapSettings.iEnabledEncapsulatedEAPExpandedTypes.Append(tmpEap);

                qDebug()
                    << "EapQtConfigInterfacePrivate::copyToEapSettings() - Added to InnerType: "
                    << tmpHandle.type().eapExpandedData().toHex();
            }
        }
    }

    varValue = config.value(EapQtConfig::CipherSuites);
    if (varValue.type() == QVariant::List) {

        qDebug() << "EapQtConfigInterfacePrivate::copyToEapSettings() - CipherSuites present";
        QList<QVariant> varCiphers = varValue.toList();

        for (ind = 0; ind < varCiphers.count(); ind++) {
            // check that the item is of correct type (int also accepted to not be too strict)
            if (varCiphers[ind].type() == QVariant::UInt || varCiphers[ind].type() == QVariant::Int) {
                // set to true only if at least item cipher is ok
                eapSettings.iCipherSuitesPresent = ETrue;
                eapSettings.iCipherSuites.Append(varCiphers[ind].toUInt());
                qDebug(
                    "EapQtConfigInterfacePrivate::copyToEapSettings() - CipherSuites at %d: 0x%08x",
                    ind, varCiphers[ind].toUInt());
            }
        }
    }

    varValue = config.value(EapQtConfig::AuthorityCertificate);
    if (varValue.type() == QVariant::List) {

        qDebug()
            << "EapQtConfigInterfacePrivate::copyToEapSettings() - AuthorityCertificate present";

        QList<QVariant> varCerts = varValue.toList();
        for (ind = 0; ind < varCerts.count(); ind++) {
            // check that the item is of correct type
            if (varCerts[ind].canConvert<EapQtCertificateInfo> ()) {
                // set to true only if at least one item is ok
                eapSettings.iCertificatesPresent = ETrue;
                appendCertificateInfo(true, varCerts[ind].value<EapQtCertificateInfo> (),
                    &(eapSettings.iCertificates));
                qDebug()
                    << "EapQtConfigInterfacePrivate::copyToEapSettings() - AuthorityCertificate appended";
            }
        }
    }

    varValue = config.value(EapQtConfig::UserCertificate);
    if (varValue.type() == QVariant::List) {

        qDebug() << "EapQtConfigInterfacePrivate::copyToEapSettings() - UserCertificate present";

        QList<QVariant> varCerts = varValue.toList();
        for (ind = 0; ind < varCerts.count(); ind++) {
            // check that the item is of correct type
            if (varCerts[ind].canConvert<EapQtCertificateInfo> ()) {
                // set to true only if at least one item is ok
                eapSettings.iCertificatesPresent = ETrue;
                appendCertificateInfo(false, varCerts[ind].value<EapQtCertificateInfo> (),
                    &(eapSettings.iCertificates));
                qDebug()
                    << "EapQtConfigInterfacePrivate::copyToEapSettings() - AuthorityCertificate appended";
            }
        }
    }

}

// caller takes care of deallocating resulting data in certList
void EapQtConfigInterfacePrivate::appendCertificateInfo(bool isCaCertificate,
    const EapQtCertificateInfo& certInfo, RPointerArray<EapCertificateEntry>* const certList)
{
    qDebug("EapQtConfigInterfacePrivate::appendCertificateInfo(), this = 0x%08x", this);


    Q_ASSERT(certList);

    // use scoped pointer to make sure memory is not leaked in failures
    QScopedPointer<EapCertificateEntry> certEntry(new EapCertificateEntry);

    // set certificate enabled in EAP settings
    certEntry->SetIsEnabledPresent();
    certEntry->SetIsEnabled(ETrue);

    if (isCaCertificate) {
        qDebug("EapQtConfigInterfacePrivate::appendCertificateInfo() - CA certificate");
        certEntry->SetCertType(EapCertificateEntry::ECA);
    }
    else {
        qDebug("EapQtConfigInterfacePrivate::appendCertificateInfo() - Client certificate");
        certEntry->SetCertType(EapCertificateEntry::EUser);
    }

    qDebug("EapQtConfigInterfacePrivate::appendCertificateInfo() - *** Adding cert data");

    TBuf<KGeneralStringMaxLength> certText;

    QVariant varValue = certInfo.value(EapQtCertificateInfo::SubjectName);
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        certEntry->SetSubjectNamePresent();
        certText.Copy(varValue.toString().utf16());
        certEntry->SetSubjectName(certText);

        qDebug() << "EapQtConfigInterfacePrivate::appendCertificateInfo() - SubjectName: "
            << varValue.toString();
    }

    varValue = certInfo.value(EapQtCertificateInfo::IssuerName);
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        certEntry->SetIssuerNamePresent();
        certText.Copy(varValue.toString().utf16());
        certEntry->SetIssuerName(certText);

        qDebug() << "EapQtConfigInterfacePrivate::appendCertificateInfo() - IssuerName: "
            << varValue.toString();
    }

    varValue = certInfo.value(EapQtCertificateInfo::SerialNumber);
    if (varValue.type() == QVariant::String && varValue.toString().count() <= StringMaxLength) {
        certEntry->SetSerialNumberPresent();
        certText.Copy(varValue.toString().utf16());
        certEntry->SetSerialNumber(certText);

        qDebug() << "EapQtConfigInterfacePrivate::appendCertificateInfo() - SerialNumber: "
            << varValue.toString();
    }

    TCertLabel certLabel;

    varValue = certInfo.value(EapQtCertificateInfo::CertificateLabel);
    if (varValue.type() == QVariant::String && varValue.toString().count() <= CertLabelMaxLength) {
        certEntry->SetLabelPresent();
        certLabel.Copy(varValue.toString().utf16());
        certEntry->SetLabel(certLabel);

        qDebug() << "EapQtConfigInterfacePrivate::appendCertificateInfo() - CertificateLabel: "
            << varValue.toString();
    }

    TBuf<KThumbprintMaxLength> thumbPrint;

    varValue = certInfo.value(EapQtCertificateInfo::ThumbPrint);
    if (varValue.type() == QVariant::String && varValue.toString().count()
        <= CertThumbprintMaxLength) {
        certEntry->SetThumbprintPresent();
        thumbPrint.Copy(varValue.toString().utf16());
        certEntry->SetThumbprint(thumbPrint);

        qDebug() << "EapQtConfigInterfacePrivate::appendCertificateInfo() - ThumbPrint: "
            << varValue.toString();
    }

    TKeyIdentifier keyId;

    varValue = certInfo.value(EapQtCertificateInfo::SubjectKeyId);
    if (varValue.type() == QVariant::ByteArray && varValue.toByteArray().count()
        <= CertSubjectKeyIdLength) {
        certEntry->SetSubjectKeyIdPresent();
        keyId.Copy(reinterpret_cast<unsigned char*> (varValue.toByteArray().data()),
            varValue.toByteArray().size());
        certEntry->SetSubjectKeyId(keyId);

        qDebug() << "EapQtConfigInterfacePrivate::appendCertificateInfo() - SubjectKeyId: "
            << varValue.toByteArray().toHex();
    }

    // EapSettings destructor takes care of deallocating the entry
    certList->Append(certEntry.data());

    qDebug()
        << "EapQtConfigInterfacePrivate::appendCertificateInfo()"
        << "- *** certificate appended to list";

    // all ok, remove the ownerhsip from scoped pointer
    (void) certEntry.take();
}

void EapQtConfigInterfacePrivate::copyFromEapSettings(EAPSettings& eapSettings, EapQtConfig& config)
{
    qDebug("EapQtConfigInterfacePrivate::copyFromEapSettings(), this = 0x%08x", this);

    int ind = 0;

    // automatic username
    if (eapSettings.iUseAutomaticUsernamePresent) {
        config.setValue(EapQtConfig::UsernameAutomatic, convertToBool(
            eapSettings.iUseAutomaticUsername));
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings UsernameAutomatic: "
            << config.value(EapQtConfig::UsernameAutomatic).toBool();
    }

    // automatic CA certificate
    if (eapSettings.iUseAutomaticCACertificatePresent) {
        config.setValue(EapQtConfig::AuthorityCertificateAutomatic, convertToBool(
            eapSettings.iUseAutomaticCACertificate));
        qDebug()
            << "EapQtConfigInterfacePrivate - copyFromEapSettings AuthorityCertificateAutomatic: "
            << config.value(EapQtConfig::AuthorityCertificateAutomatic).toBool();
    }

    // username
    if (eapSettings.iUsernamePresent) {
        config.setValue(EapQtConfig::Username, QString::fromUtf16(eapSettings.iUsername.Ptr(),
            eapSettings.iUsername.Length()));
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings Username: " << config.value(
            EapQtConfig::Username).toString();
    }

    // password existence check, password itself is write-only, cannot be read
    if (eapSettings.iPasswordExistPresent) {
        // report to caller if password exists in the database
        config.setValue(EapQtConfig::PasswordStored, convertToBool(eapSettings.iPasswordExist));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings PasswordStored: "
            << config.value(EapQtConfig::PasswordStored).toBool();
    }

    // password prompt
    if (eapSettings.iShowPassWordPromptPresent) {
        config.setValue(EapQtConfig::PasswordPrompt, convertToBool(eapSettings.iShowPassWordPrompt));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings PasswordPrompt: "
            << config.value(EapQtConfig::PasswordPrompt).toBool();
    }

    // automatic realm
    if (eapSettings.iUseAutomaticRealmPresent) {
        config.setValue(EapQtConfig::RealmAutomatic, convertToBool(eapSettings.iUseAutomaticRealm));
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings RealmAutomatic: "
            << config.value(EapQtConfig::RealmAutomatic).toBool();
    }

    // realm
    if (eapSettings.iRealmPresent) {
        config.setValue(EapQtConfig::Realm, QString::fromUtf16(eapSettings.iRealm.Ptr(),
            eapSettings.iRealm.Length()));
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings Realm: " << config.value(
            EapQtConfig::Realm).toString();
    }

    // server name
    if (eapSettings.iVerifyServerRealmPresent) {
        config.setValue(EapQtConfig::VerifyServerRealm, convertToBool(
            eapSettings.iVerifyServerRealm));
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings VerifyServerRealm: "
            << config.value(EapQtConfig::VerifyServerRealm).toBool();
    }

    // pseudonym
    if (eapSettings.iUsePseudonymsPresent) {
        config.setValue(EapQtConfig::UsePseudonyms, convertToBool(eapSettings.iUsePseudonyms));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings UsePseudonyms: "
            << config.value(EapQtConfig::UsePseudonyms).toBool();
    }

    // policy: server must require client authentication
    if (eapSettings.iRequireClientAuthenticationPresent) {
        config.setValue(EapQtConfig::ClientAuthenticationRequired, convertToBool(
            eapSettings.iRequireClientAuthentication));

        qDebug()
            << "EapQtConfigInterfacePrivate - copyFromEapSettings ClientAuthenticationRequired: "
            << config.value(EapQtConfig::ClientAuthenticationRequired).toBool();
    }

    // session validity time
    if (eapSettings.iSessionValidityTimePresent) {
        config.setValue(EapQtConfig::SessionValidityTime, eapSettings.iSessionValidityTime);

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings SessionValidityTime: "
            << config.value(EapQtConfig::SessionValidityTime).toUInt();
    }

    // TLS ciphersuites
    if (eapSettings.iCipherSuitesPresent) {
        QList<QVariant> ciphers; // QVariant has a constructor for uint
        for (ind = 0; ind < eapSettings.iCipherSuites.Count(); ind++) {
            ciphers.append(eapSettings.iCipherSuites[ind]);
            qDebug("EapQtConfigInterfacePrivate - copyFromEapSettings CipherSuites at %d: 0x%08x",
                ind, ciphers[ind].toUInt());
        }
        config.setValue(EapQtConfig::CipherSuites, ciphers);
    }

    // certificates
    if (eapSettings.iCertificatesPresent) {

        QList<EapQtCertificateInfo> caCerts;
        QList<EapQtCertificateInfo> clientCerts;
        RPointerArray<EapCertificateEntry> serverCaCerts;
        RPointerArray<EapCertificateEntry> serverClientCerts;

        // separate CA and client certs to their own lists
        for (ind = 0; ind < eapSettings.iCertificates.Count(); ind++) {

            qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings certificates, "
                << "cert type: " << eapSettings.iCertificates[ind]->GetCertType() << ", enabled: "
                << convertToBool(eapSettings.iCertificates[ind]->GetIsEnabled());

            // only enabled certificates are reported
            if (eapSettings.iCertificates[ind]->GetCertType() == EapCertificateEntry::EUser
                && eapSettings.iCertificates[ind]->GetIsEnabled() != EFalse) {
                serverClientCerts.Append(eapSettings.iCertificates[ind]);
            }
            // only enabled certificates are reported
            else if (eapSettings.iCertificates[ind]->GetCertType() == EapCertificateEntry::ECA
                && eapSettings.iCertificates[ind]->GetIsEnabled() != EFalse) {
                serverCaCerts.Append(eapSettings.iCertificates[ind]);
            }
            else {
                qDebug()
                    << "WARNING: EapQtConfigInterfacePrivate - copyFromEapSettings certificates, "
                    << "unknown certificate type in the list or certificate not enabled";
            }
        }

        // copy to lists of our type
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings AuthorityCertificates";
        copyCertificateInfo(&serverCaCerts, &caCerts);
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings UserCertificates";
        copyCertificateInfo(&serverClientCerts, &clientCerts);

        // reset the arrays, data is owned by EapSettings.h,
        // must not be destroyed here
        serverCaCerts.Reset();
        serverClientCerts.Reset();

        // we still need to convert QList<EapQtCertificateInfo> to QList<QVariant>
        // to be able to store to config
        QVariant tmp;
        QList<QVariant> varCaCerts;
        QList<QVariant> varClientCerts;

        for (ind = 0; ind < caCerts.count(); ind++) {
            tmp.setValue(caCerts[ind]);
            varCaCerts.append(tmp);
        }
        for (ind = 0; ind < clientCerts.count(); ind++) {
            tmp.setValue(clientCerts[ind]);
            varClientCerts.append(tmp);
        }

        // finally copy to config
        config.setValue(EapQtConfig::AuthorityCertificate, varCaCerts);
        config.setValue(EapQtConfig::UserCertificate, varClientCerts);
    }

    // PEAP specific
    if (eapSettings.iPEAPVersionsPresent) {
        config.setValue(EapQtConfig::PeapVersion0Allowed, convertToBool(eapSettings.iPEAPv0Allowed));
        config.setValue(EapQtConfig::PeapVersion1Allowed, convertToBool(eapSettings.iPEAPv1Allowed));
        config.setValue(EapQtConfig::PeapVersion2Allowed, convertToBool(eapSettings.iPEAPv2Allowed));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings PeapVersion0Allowed: "
            << config.value(EapQtConfig::PeapVersion0Allowed).toBool();
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings PeapVersion1Allowed: "
            << config.value(EapQtConfig::PeapVersion1Allowed).toBool();
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings PeapVersion2Allowed: "
            << config.value(EapQtConfig::PeapVersion2Allowed).toBool();
    }

    // TLS privacy
    if (eapSettings.iUseIdentityPrivacyPresent) {
        config.setValue(EapQtConfig::UseIdentityPrivacy, convertToBool(
            eapSettings.iUseIdentityPrivacy));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings UseIdentityPrivacy: "
            << config.value(EapQtConfig::UseIdentityPrivacy).toBool();
    }

    // EAP-FAST specific
    if (eapSettings.iAuthProvModeAllowedPresent) {
        config.setValue(EapQtConfig::ProvisioningModeAuthenticated, convertToBool(
            eapSettings.iAuthProvModeAllowed));

        qDebug()
            << "EapQtConfigInterfacePrivate - copyFromEapSettings ProvisioningModeAuthenticated: "
            << config.value(EapQtConfig::ProvisioningModeAuthenticated).toBool();
    }
    if (eapSettings.iUnauthProvModeAllowedPresent) {
        config.setValue(EapQtConfig::ProvisioningModeUnauthenticated, convertToBool(
            eapSettings.iUnauthProvModeAllowed));

        qDebug()
            << "EapQtConfigInterfacePrivate - copyFromEapSettings ProvisioningModeUnauthenticated: "
            << config.value(EapQtConfig::ProvisioningModeUnauthenticated).toBool();
    }
    if (eapSettings.iWarnADHPNoPACPresent) {
        config.setValue(EapQtConfig::WarnADHPNoPAC, convertToBool(eapSettings.iWarnADHPNoPAC));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings WarnADHPNoPAC: "
            << config.value(EapQtConfig::WarnADHPNoPAC).toBool();
    }
    if (eapSettings.iWarnADHPNoMatchingPACPresent) {
        config.setValue(EapQtConfig::WarnADHPNoMatchingPAC, convertToBool(
            eapSettings.iWarnADHPNoMatchingPAC));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings WarnADHPNoMatchingPAC: "
            << config.value(EapQtConfig::WarnADHPNoMatchingPAC).toBool();
    }
    if (eapSettings.iWarnNotDefaultServerPresent) {
        config.setValue(EapQtConfig::WarnNotDefaultServer, convertToBool(
            eapSettings.iWarnNotDefaultServer));

        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings WarnNotDefaultServer: "
            << config.value(EapQtConfig::WarnNotDefaultServer).toBool();
    }
    if (eapSettings.iPACGroupReferencePresent) {
        config.setValue(EapQtConfig::PACGroupReference, QString::fromUtf16(
            eapSettings.iPACGroupReference.Ptr(), eapSettings.iPACGroupReference.Length()));
        qDebug() << "EapQtConfigInterfacePrivate - copyFromEapSettings PACGroupReference: "
            << config.value(EapQtConfig::PACGroupReference).toString();
    }

    // enabled inner EAPs
    if (eapSettings.iEnabledEncapsulatedEAPExpandedTypesPresent) {

        qDebug("EapQtConfigInterfacePrivate - copyFromEapSettings InnerType, enabled count %d",
            eapSettings.iEnabledEncapsulatedEAPExpandedTypes.Count());

        QList<QByteArray> innerEapsOn;
        appendEapTypes(&(eapSettings.iEnabledEncapsulatedEAPExpandedTypes), &innerEapsOn);

        // convert to QList<QVariant> to be able to store to config
        QVariant varTmp;
        QList<QVariant> varInnerEapsOn;
        int dummy = 0;

        for (ind = 0; ind < innerEapsOn.count(); ind++) {
            // report only EAPs which do have an UI plugin
            if (isUiSupported(innerEapsOn[ind], dummy)) {
                // create plugin handle from EAP type with constructors
                // calls: EapQtExpandedEapType(const QByteArray data) -> EapQtPluginHandle(EapQtExpandedEapType type)
                varTmp.setValue(EapQtPluginHandle(EapQtExpandedEapType(innerEapsOn[ind])));
                varInnerEapsOn.append(varTmp);
                qDebug()
                    << "EapQtConfigInterfacePrivate - copyFromEapSettings InnerType: added EAP: "
                    << innerEapsOn[ind].toHex();
            }
        }

        // copy to config
        config.setValue(EapQtConfig::InnerType, varInnerEapsOn);
    }

    // disabled inner EAPs
    if (eapSettings.iDisabledEncapsulatedEAPExpandedTypesPresent) {
        // setting is not needed, enabled are enough
        qDebug(
            "EapQtConfigInterfacePrivate - copyFromEapSettings InnerType: disabled count %d (not needed for anything here)",
            eapSettings.iDisabledEncapsulatedEAPExpandedTypes.Count());
    }

}

QList<EapQtPluginHandle> EapQtConfigInterfacePrivate::selectedOuterTypes()
{
    qDebug("EapQtConfigInterfacePrivate::selectedOuterTypes(), this = 0x%08x", this);


    checkInstanceThrowing();

    if (!mEapDbIndexValid) {
        qDebug() << "ERROR: Database reference not valid, call setConfigurationReference first!";
        return QList<EapQtPluginHandle> ();
    }

    // call to make sure the members (mOuterEapsOn and mSupportedOuterTypes) are up-to-date
    (void) supportedOuterTypes();

    QList<EapQtPluginHandle> selectedOuterTypes;

    QList<QByteArray> tmpEaps;
    appendEapTypes(&mOuterEapsOn, &tmpEaps);

    // report only the ones that also have an UI, i.e. listed in mSupportedOuterTypes
    for (int ind = 0; ind < mSupportedOuterTypes.count(); ind++) {
        if (tmpEaps.contains(mSupportedOuterTypes[ind].pluginHandle().type().eapExpandedData())) {
            selectedOuterTypes.append(mSupportedOuterTypes[ind].pluginHandle());
        }
    }

    qDebug("EapQtConfigInterfacePrivate - selected outer type count: %d",
        selectedOuterTypes.count());

    return selectedOuterTypes;
}

bool EapQtConfigInterfacePrivate::isSupportedOuterType(const EapQtPluginHandle& handle)
{
    qDebug("EapQtConfigInterfacePrivate::isSupportedOuterType(), this = 0x%08x", this);


    checkInstanceThrowing();

    // check if mSupportedOuterTypes is up-to-date
    if (mSupportedOuterTypes.count() <= 0) {
        // update mSupportedOuterTypes
        (void) supportedOuterTypes();
    }

    bool ret = false;
    for (int ind = 0; ind < mSupportedOuterTypes.count(); ind++) {
        if (mSupportedOuterTypes[ind].pluginHandle() == handle) {
            ret = true;
        }
    }
    return ret;
}

bool EapQtConfigInterfacePrivate::setSelectedOuterTypes(
    const QList<EapQtPluginHandle>& outerHandles)
{
    qDebug("EapQtConfigInterfacePrivate::setSelectedOuterTypes()");


    checkInstanceThrowing();

    if (!mEapDbIndexValid || mEapGsIf.isNull()) {
        qDebug()
            << "ERROR: Database reference not valid (or mEapGsIf is NULL), call setConfigurationReference first!";
        return false;
    }

    // check if mSupportedOuterTypes is up-to-date
    if (mSupportedOuterTypes.count() <= 0) {
        // update mSupportedOuterTypes
        (void) supportedOuterTypes();
    }

    // clear arrays
    mOuterEapsOn.Reset();
    mOuterEapsOff.Reset();

    // pick only the supported ones from outerHandles
    TEapExpandedType tmpEap;
    for (int ind = 0; ind < mSupportedOuterTypes.count(); ind++) {
        if (outerHandles.contains(mSupportedOuterTypes[ind].pluginHandle())) {

            // convert to TEapExpandedType
            tmpEap.SetValue(
                mSupportedOuterTypes[ind].pluginHandle().type().eapExpandedData().data(),
                mSupportedOuterTypes[ind].pluginHandle().type().eapExpandedData().length());

            // add to mOuterEapsOn
            mOuterEapsOn.Append(tmpEap);

            qDebug()
                << "EapQtConfigInterfacePrivate - setSelectedOuterTypes adding to enabledOuterHandles: "
                << mSupportedOuterTypes[ind].pluginHandle().type().eapExpandedData().toHex();
        }
    }

    bool ret = true;

    // set selection to EAP server, no need to have correct content in mOuterEapsOff,  
    // EAP server handles it, mOuterEapsOn is only important
    TUint err = mEapGsIf->SetEapMethods(mOuterEapsOn, mOuterEapsOff);
    if (err != KErrNone) {
        qDebug("EapQtConfigInterfacePrivate::setSelectedOuterTypes() - SetEapMethods failed: %d",
            err);
        // nothing we can do to recover, just exit
        ret = false;
    }
    return ret;
}

bool EapQtConfigInterfacePrivate::isSupportedInnerType(const EapQtPluginHandle& outerHandle,
    const EapQtPluginHandle& innerHandle)
{
    qDebug("EapQtConfigInterfacePrivate::isSupportedInnerType(), this = 0x%08x", this);


    checkInstanceThrowing();

    // update mSupportedInnerTypes
    (void) supportedInnerTypes(outerHandle);

    for (int ind = 0; ind < mSupportedInnerTypes.count(); ind++) {
        if (mSupportedInnerTypes[ind].pluginHandle() == innerHandle) {
            return true;
        }
    }
    return false;
}

bool EapQtConfigInterfacePrivate::deleteConfiguration()
{
    qDebug("EapQtConfigInterfacePrivate::deleteConfiguration(), this = 0x%08x", this);


    checkInstanceThrowing();

    if (!mEapDbIndexValid || mEapGsIf.isNull()) {
        qDebug()
            << "ERROR: Database reference not valid (or mEapGsIf is NULL), call setConfigurationReference first!";
        return false;
    }

    bool ret = true;
    TInt err = mEapGsIf->DeleteAllEapSettings();
    if (err != KErrNone) {
        ret = false;
    }
    return ret;
}

void EapQtConfigInterfacePrivate::loadPlugins()
{
    qDebug("EapQtConfigInterfacePrivate::loadPlugins(), this = 0x%08x", this);

    checkInstanceThrowing();

    QDir pluginsDir(eapPluginDir);
    foreach( QString fileName, pluginsDir.entryList(QDir::Files) )
        {
            QPluginLoader loader(pluginsDir.absoluteFilePath(fileName));
            QObject *tmp = loader.instance();
            if (tmp) {
                CpEapPluginInterface *plugin = qobject_cast<CpEapPluginInterface*> (tmp);
                if (plugin) {
                    mPlugins.append(plugin);
                }
            }
        }

    // collect UI plugin infos
    QList<CpEapPluginInterface*>::iterator iter;
    for (iter = mPlugins.begin(); iter != mPlugins.end(); ++iter) {
        mPluginInfos.append((*iter)->pluginInfo());
    }
}

CpBaseSettingView *EapQtConfigInterfacePrivate::uiInstance(const EapQtPluginHandle& outerHandle,
    const EapQtPluginHandle& pluginHandle)
{
    qDebug("EapQtConfigInterfacePrivate::uiInstance(), this = 0x%08x", this);


    checkInstanceThrowing();

    // if outer type UI is requested, outerHandle must be undefined and pluginHandle
    // must be supported as outer type
    if (outerHandle == EapQtPluginHandle::PluginUndefined) {
        if (!isSupportedOuterType(pluginHandle)) {
            qDebug() << "ERROR: EapQtConfigInterfacePrivate::uiInstance() -"
                << "plugin not supported as outer type";
            return NULL;
        }
    }
    else {
        // outerHandle defined, pluginHandle must be supported inside outerHandle
        if (!isSupportedInnerType(outerHandle, pluginHandle)) {
            qDebug() << "ERROR: EapQtConfigInterfacePrivate::uiInstance() -"
                << "plugin not supported as the inner type of the specified outer type";
            return NULL;
        }
    }

    if (mTranslator.isNull()) {
        // install translations for EAP UI plugins
        mTranslator.reset(new HbTranslator(eapTranslationFile));
    }

    // go through all interfaces (dlls)
    QList<CpEapPluginInterface*>::iterator iter;
    for (iter = mPlugins.begin(); iter != mPlugins.end(); ++iter) {
        QList<EapQtPluginInfo> plugins;
        plugins.append((*iter)->pluginInfo());

        // go through all plugings inside the interface implementation
        QList<EapQtPluginInfo>::iterator j;
        for (j = plugins.begin(); j != plugins.end(); ++j) {
            if ((*j).pluginHandle() == pluginHandle) {
                qDebug("EapQtConfigInterfacePrivate::uiInstance() - found plugin");
                // indicate configured IAP to plugin
                (*iter)->setSettingsReference(getEapBearer(), mIapId);
                return (*iter)->uiInstance(outerHandle, *j);
            }
        }

    }
    qDebug("ERROR: EapQtConfigInterfacePrivate::uiInstance() - plugin not found");
    return NULL;
}

EapQtConfigInterface::EapBearerType EapQtConfigInterfacePrivate::getEapBearer()
{
    EapQtConfigInterface::EapBearerType ret(EapQtConfigInterface::EapBearerTypeWlan);

    switch (mEapBearer) {
    case EVpn:
        ret = EapQtConfigInterface::EapBearerTypeVpn;
        break;
    default:
        ret = EapQtConfigInterface::EapBearerTypeWlan;
        break;
    }
    return ret;
}

EapQtValidator *EapQtConfigInterfacePrivate::validatorEap(EapQtExpandedEapType type,
    EapQtConfig::SettingsId id)
{
    qDebug("EapQtConfigInterfacePrivate::validatorEap(), this = 0x%08x", this);


    EapQtValidator *ret = NULL;

    switch (id) {

    case EapQtConfig::Username:
        switch (type.type()) {
        case EapQtExpandedEapType::TypeEapAka:
        case EapQtExpandedEapType::TypeEapFast:
        case EapQtExpandedEapType::TypeEapGtc:
        case EapQtExpandedEapType::TypeLeap:
        case EapQtExpandedEapType::TypeEapMschapv2:
        case EapQtExpandedEapType::TypePeap:
        case EapQtExpandedEapType::TypeEapSim:
        case EapQtExpandedEapType::TypeEapTls:
        case EapQtExpandedEapType::TypeEapTtls:
        case EapQtExpandedEapType::TypePap:
        case EapQtExpandedEapType::TypePlainMschapv2:
            ret = new EapQtValidatorUsername(type);
            break;
        default:
            ret = NULL;
        }
        break;

    case EapQtConfig::Password:
        switch (type.type()) {
        case EapQtExpandedEapType::TypeEapGtc:
        case EapQtExpandedEapType::TypeLeap:
        case EapQtExpandedEapType::TypeEapMschapv2:
        case EapQtExpandedEapType::TypePap:
        case EapQtExpandedEapType::TypePlainMschapv2:
            ret = new EapQtValidatorPassword(type);
            break;
        default:
            ret = NULL;
        }
        break;

    case EapQtConfig::Realm:
        switch (type.type()) {
        case EapQtExpandedEapType::TypeEapAka:
        case EapQtExpandedEapType::TypeEapFast:
        case EapQtExpandedEapType::TypePeap:
        case EapQtExpandedEapType::TypeEapSim:
        case EapQtExpandedEapType::TypeEapTls:
        case EapQtExpandedEapType::TypeEapTtls:
            ret = new EapQtValidatorRealm(type);
            break;
        default:
            ret = NULL;
        }
        break;

    default:
        ret = NULL;

    }

    return ret;
}
