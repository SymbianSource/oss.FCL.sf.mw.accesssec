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
 *    Control Panel QT UI for WPA/WPA2 configuration
 *
 */

/*
 * %version: tr1cfwln#21.1.1 %
 */
//User Includes
#include "cpwpaui.h"
#include "cpwpacmnui.h"
#include "wpakeyvalidator.h"

// System includes
#include <QStringList>
#include <HbDeviceNotificationDialog>
#include <QLocale>
#include <qtranslator.h>
#include <QCoreApplication>
#include <cmconnectionmethod_shim.h>
#include <cmmanagerdefines_shim.h>
#include <eapqtconfiginterface.h>

#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpauiTraces.h"
#endif

//Constants
//The order in which WPA/WPA2 only mode appears in the list of available 
//security modes
const int UI_ORDER_WPA_WPA2 = 40;
/*!
 \class CpWpaUi
 \brief CpWpaUi implements the common Ui for WPA/WPA2 
 Security Settings Control Panel Plugins,
 which will allow viewing/editing of WPA/WPA2 Security Settings.
 */
//Contructs WPA/WPA2 object
CpWpaUi::CpWpaUi() :
    mUi(NULL), mCmCM(NULL), mEapQtConfigInterface(NULL)
{
    mTranslator = new QTranslator(this);
    mTranslator->load(":/loc/wlan_en_GB.qm");

    qApp->installTranslator(mTranslator);

}

//Deletes all objects WPA/WPA2 owns
CpWpaUi::~CpWpaUi()
{
    OstTraceFunctionEntry1(CPWPAUI_CPWPAUI_ENTRY,this);
    //delete mEapQtConfigInterface;
    OstTraceFunctionExit1(CPWPAUI_CPWPAUI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========

/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWpaUi::securityMode() const
{
    OstTraceFunctionEntry1(CPWPAUI_MODE_ENTRY,this);
    OstTraceFunctionExit1(CPWPAUI_MODE_EXIT,this);
    //return security mode
    return CMManagerShim::WlanSecModeWpa;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_wpawpa2". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString CpWpaUi::securityModeTextId() const
{
    OstTraceFunctionEntry1(CPWPAUI_LOCALIZATIONID_ENTRY,this); 
    OstTraceFunctionExit1(CPWPAUI_LOCALIZATIONID_EXIT,this);
    return "txt_occ_setlabel_wlan_security_mode_val_wpawpa2";
}

/*! 
 Sets the database reference (WLAN Service Table ID).

 \param id Database reference
 */
void CpWpaUi::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceFunctionEntry1(CPWPAUI_SETREFERENCE_ENTRY,this);
    // Assuming that id is the connection method Id/IAP Id.
    mCmId = id;

    /*if (!mEapQtConfigInterface) {
     mEapQtConfigInterface = new EapQtConfigInterface(
     EapQtConfigInterface::EapBearerTypeWlan, mCmId);
     // fix, hangs
     }*/

    //mCmCM is not deleted assuming mCmManager owns it.
    mCmCM = cmCm;
    OstTraceFunctionExit1(CPWPAUI_SETREFERENCE_EXIT,this);
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int CpWpaUi::orderNumber() const
{
    OstTraceFunctionEntry1(CPWPAUI_ORDERNUMBER_ENTRY,this); 
    OstTraceFunctionExit1(CPWPAUI_ORDERNUMBER_EXIT,this);
    return UI_ORDER_WPA_WPA2;
}

/*!
 Creates an UI instance. Caller owns the object.
 
 \param dataHelper Item data helper
 \return Pointer to an UI object
 */
CpSettingFormItemData* CpWpaUi::uiInstance(CpItemDataHelper &dataHelper)
{
    OstTraceFunctionEntry1(CPWPAUI_UIINSTANCE_ENTRY,this);

		//reset the Common Ui Ptr
    mWpaUi.reset(new CpWpaCmnUi(CMManagerShim::WlanSecModeWpa, dataHelper));

    mUi = mWpaUi->createUi(mEapQtConfigInterface, mCmCM);

    connect(mWpaUi.data(), SIGNAL(keyChanged(QString&)), this, SLOT(pskKeyChanged(QString&)));

    connect(mWpaUi.data(), SIGNAL(pskEapModeToggled(int)), this, SLOT(wpaTypeChanged(int)));

    connect(mWpaUi.data(), SIGNAL(eapPluginChanged(int)), this, SLOT(currentEapPlugin(int)));
    //}
    OstTraceFunctionExit1(CPWPAUI_UIINSTANCE_EXIT,this);
    return mUi;
}


// ======== LOCAL FUNCTIONS ========

/*!
 Slot to handle change in wpa mode :- PSK /EAP

 \param pskEnable the current mode chosen
 */
/*void CpWpaUi::wpaTypeChanged(int pskEnable)
{
    int err;
    OstTraceFunctionEntry1(CPWPAUI_WPATYPECHANGED_ENTRY,this);

    bool PskEnable = pskEnable ? ETrue : EFalse;

    QT_TRYCATCH_ERROR(err,mCmCM->setBoolAttribute(CMManagerShim::WlanEnableWpaPsk, PskEnable));
    
    if(err !=KErrNone) {
              OstTrace1( TRACE_ERROR, CPWPAUI_WPATYPECHANGED, "ERROR WPA/WPA2 wpatypereturned returned %d", err );
    }
    tryUpdate();
    OstTraceFunctionExit1(CPWPAUI_WPATYPECHANGED_EXIT,this);
}*/

/*!
 Slot to handle change in pre-shared key string

 \param key changed string for PSK
 */
void CpWpaUi::pskKeyChanged(QString &key)
{
    int err;
    OstTraceFunctionEntry1(CPWPAUI_PSKKEYCHANGED_ENTRY,this);
    //Store to native s60 type for validation 
    TPtrC ptrName(reinterpret_cast<const TText*> (key.constData()));

    //Check for Validity of Pre-shared Key
    WpaKeyValidator::KeyStatus keystatus = WpaKeyValidator::validateWpaKey(key);

    if (keystatus == WpaKeyValidator::KeyStatusOk) {

        QT_TRYCATCH_ERROR(err,mCmCM->setString8Attribute(CMManagerShim::WlanWpaPreSharedKey, key));
        if(err !=KErrNone) {
          OstTrace1( TRACE_ERROR,CPWPAUI_PSKKEYCHANGED, "ERROR WPA/WPA2: pskKeyChanged returned %d", err );
        }
        tryUpdate();
    }
    else {
    showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
                      "txt_occ_info_invalid_input"));
    }
    OstTraceFunctionExit1(CPWPAUI_PSKKEYCHANGED_EXIT,this);
}

/*!
 Slot to handle change in eap method in use
 \param currentplugin plugin number to indicate the
 eap method in use
 */
/*void CpWpaUi::currentEapPlugin(int  plugin )
{
    OstTraceFunctionEntry1(CPWPAUI_CURRENTEAPPLUGIN_ENTRY,this);

    //define enum to store the current EAP type
    //mCmCM->setIntAttribute( use appropriate enum to get the eap plugin index );
    OstTraceFunctionExit1(CPWPAUI_CURRENTEAPPLUGIN_EXIT,this);
}*/

bool CpWpaUi::tryUpdate()
{
    OstTraceFunctionEntry1(CPWPAUI_TRYUPDATE_ENTRY,this);

    // Try update
    try {
        mCmCM->update();
    } catch (const std::exception&) {
        // Handle error
        handleUpdateError();

        OstTraceFunctionExit1(CPWPAUI_TRYUPDATE_EXIT,this);
        return false;
    }

    OstTraceFunctionExit1(DUP1_CPWPAUI_TRYUPDATE_EXIT,this);
    return true;
}

/*!
 Handles failed CommsDat update.
 */
void CpWpaUi::handleUpdateError()
{
    OstTraceFunctionEntry1(CPWPAUI_HANDLEUPDATEERROR_ENTRY,this);

    // Show error note to user
    showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId("txt_occ_info_unable_to_save_setting"));
    // Reload settings from CommsDat and update UI
    try {
        mCmCM->refresh();
    } catch (const std::exception&) {
        // Ignore error from refresh. Most likely this will not happen, but
        // if it does, there isn't very much we can do.
        OstTrace0(
            TRACE_ERROR,
            CPWPAUI_HANDLEUPDATEERROR,
            "Refresh failed");
    };
    updateWpaSettings();

    OstTraceFunctionExit1(CPWPAUI_HANDLEUPDATEERROR_EXIT,this);
}

/*!
 Shows message box with "OK" button using given text.
 */
void CpWpaUi::showMessageBox(HbMessageBox::MessageBoxType type, const QString &text)
{
    OstTraceFunctionEntry1(CPWPAUI_SHOWMESSAGEBOX_ENTRY,this);

    // Create a message box
    mMessageBox = QSharedPointer<HbMessageBox> (new HbMessageBox(type));
    mMessageBox->setText(text);
    mMessageBox->open();

    OstTraceFunctionExit1(CPWPAUI_SHOWMESSAGEBOX_EXIT,this);
}

void CpWpaUi::updateWpaSettings()
{
    OstTraceFunctionEntry1(CPWPAUI_UPDATEWPASETTINGS_ENTRY,this);
    mWpaUi->reset();
    OstTraceFunctionExit1(CPWPAUI_UPDATEWPASETTINGS_EXIT,this);
}

Q_EXPORT_PLUGIN2(CpWpaUi, CpWpaUi)
;
