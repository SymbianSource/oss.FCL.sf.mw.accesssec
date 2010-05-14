/* Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
 *    Control Panel QT UI for WPA2 only configuration
 *
 */

/*
 * %version: 17 %
 */

// User includes
#include "cpwpa2ui.h"
#include "cpwpacmnui.h"
#include "wpa2keyvalidator.h"

// System includes
#include <HbDeviceNotificationDialog>
#include <cmmanagerdefines_shim.h>
#include <cmconnectionmethod_shim.h>
#include <eapqtconfiginterface.h>
#include <QStringList>
#include <QLocale>
#include <QCoreApplication>

#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpa2uiTraces.h"
#endif


// Constants
//The order in which WPA2 only mode appears in the list of available 
//security mode
const int UI_ORDER_WPA2_ONLY = 50;

/*!
 \class CpWpa2Ui
 \brief CpWpa2Ui implements the  Ui for WPA2 only 
 Security Settings Control Panel Plugin,
 which will allow viewing/editing of WPA2 only Security Settings.
 */
//Contructs WPA2 object
CpWpa2Ui::CpWpa2Ui() :
    mUi(NULL),  mCmCM(NULL), mEapQtConfigInterface(NULL),
            mWpa2Ui(NULL)
{
    mTranslator = new QTranslator(this);
    mTranslator->load(":/loc/wlan_en_GB.qm");

    qApp->installTranslator(mTranslator);
    
    /*mTranslator = QSharedPointer<HbTranslator> (
               new HbTranslator("wlan_en_GB"));*/

}

//Deletes all objects WPA2 owns
CpWpa2Ui::~CpWpa2Ui()
{
    OstTraceFunctionEntry1(CPWPA2UI_CPWPA2UI_ENTRY,this);
    //delete mEapQtConfigInterface;
    OstTraceFunctionExit1(CPWPA2UI_CPWPA2UI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========

/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWpa2Ui::securityMode() const
{
    OstTraceFunctionEntry1(CPWPA2UI_MODE_ENTRY,this);
    OstTraceFunctionExit1(CPWPA2UI_MODE_EXIT,this);
    //return security mode
    return CMManagerShim::WlanSecModeWpa2;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_wpa2_only". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString CpWpa2Ui::securityModeTextId() const
{
    OstTraceFunctionEntry1(CPWPA2UI_LOCALIZATIONID_ENTRY,this);
    OstTraceFunctionExit1(CPWPA2UI_LOCALIZATIONID_EXIT,this);
    return "txt_occ_setlabel_wlan_security_mode_val_wpa2_only";
}

/*! 
 Sets the database reference (WLAN Service Table ID).

 \param id Database reference
 */
void CpWpa2Ui::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceFunctionEntry1(CPWPA2UI_SETREFERENCE_ENTRY,this);
    // Assuming that id is the connection method Id/IAP Id.

    mCmId = id;

    /*if (!mEapQtConfigInterface) {
        mEapQtConfigInterface = new EapQtConfigInterface(
                EapQtConfigInterface::EapBearerTypeWlan, mCmId);
        //fix, hangs
    }*/

    //mCmCM is not deleted assuming mCmManager owns it.
    mCmCM = cmCm;
    OstTraceFunctionExit1(CPWPA2UI_SETREFERENCE_EXIT,this);
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int CpWpa2Ui::orderNumber() const
{
    OstTraceFunctionEntry1(CPWPA2UI_ORDERNUMBER_ENTRY,this);
    OstTraceFunctionExit1(CPWPA2UI_ORDERNUMBER_EXIT,this);
    return UI_ORDER_WPA2_ONLY;
}

/*!
 Creates an UI instance. Caller owns the object.
 
 \param dataHelper Item data helper
 \return Pointer to an UI object
 */
CpSettingFormItemData* CpWpa2Ui::uiInstance(CpItemDataHelper &dataHelpper)
{
    OstTraceFunctionEntry1(CPWPA2UI_UIINSTANCE_ENTRY,this);

		//reset the Common Ui Ptr
    mWpa2Ui.reset(new CpWpaCmnUi(CMManagerShim::WlanSecModeWpa2, dataHelpper));

    mUi = mWpa2Ui->createUi(mEapQtConfigInterface, mCmCM);

    connect(mWpa2Ui.data(), SIGNAL(keyChanged(QString&)), this,
            SLOT(pskKeyChanged(QString&)));

    connect(mWpa2Ui.data(), SIGNAL(pskEapModeToggled(int)), this,
            SLOT(wpaTypeChanged(int)));

    connect(mWpa2Ui.data(), SIGNAL(eapPluginChanged(int)), this,
            SLOT(currentEapPlugin(int)));

    OstTraceFunctionExit1(CPWPA2UI_UIINSTANCE_EXIT,this);
    return mUi;
}

// ======== LOCAL FUNCTIONS ========
/*!
 Slot to handle change in wpa mode :- PSK /EAP

 \param pskEnable the current mode chosen
 */
/*void CpWpa2Ui::wpaTypeChanged(int pskEnable)
{
    int err;
    OstTraceFunctionEntry1(CPWPA2UI_WPATYPECHANGED_ENTRY,this);

    bool PskEnable = pskEnable ? ETrue : EFalse;

    QT_TRYCATCH_ERROR(err,mCmCM->setBoolAttribute(CMManagerShim::WlanEnableWpaPsk, PskEnable));

    if(err !=KErrNone) {
          OstTrace1( TRACE_ERROR, CPWPA2UI_WPATYPECHANGED, "ERROR WPA2 only:wpatypereturned returned %d", err );
    }
    tryUpdate();
    OstTraceFunctionExit1(CPWPA2UI_WPATYPECHANGED_EXIT,this);
}*/

/*!
 Slot to handle change in pre-shared key string

 \param key changed string for PSK
 */
void CpWpa2Ui::pskKeyChanged(QString &key)
{
    int err;
    OstTraceFunctionEntry1(CPWPA2UI_PSKKEYCHANGED_ENTRY,this);

    //Check for Validity of Pre-shared Key
    Wpa2KeyValidator::KeyStatus keystatus = Wpa2KeyValidator::validateWpa2Key(key);
    
    if (keystatus == Wpa2KeyValidator::KeyStatusOk) {
        QT_TRYCATCH_ERROR(err, mCmCM->setString8Attribute(CMManagerShim::WlanWpaPreSharedKey, key));
        if(err !=KErrNone) {
                 OstTrace1( TRACE_ERROR, CPWPA2UI_PSKKEYCHANGED, "ERROR WPA2 only: pskKeyChanged returned %d", err );
        }
        tryUpdate();
    }
    
    else {
    showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
                   "txt_occ_info_invalid_input"));
    }
    OstTraceFunctionExit1(CPWPA2UI_PSKKEYCHANGED_EXIT,this);
}

/*!
 Slot to handle change in eap method in use
 \param currentplugin plugin number to indicate the
 eap method in use
 */
/*void CpWpa2Ui::currentEapPlugin(int  currentPlugin  )
{
    OstTraceFunctionEntry1(CPWPA2UI_CURRENTEAPPLUGIN_ENTRY,this);

    // define enum to store the current EAP type
    //mCmCM->setIntAttribute( use appropriate enum to get the eap plugin index );
    OstTraceFunctionExit1(CPWPA2UI_CURRENTEAPPLUGIN_EXIT,this);
}*/

bool CpWpa2Ui::tryUpdate()
{
    OstTraceFunctionEntry1(CPWPA2UI_TRYUPDATE_ENTRY,this);
    
    // Try update
    try {
        mCmCM->update();
    }
    catch (const std::exception&) {
        // Handle error
        handleUpdateError();
        
        OstTraceFunctionExit1(CPWPA2UI_TRYUPDATE_EXIT,this);
        return false;
    }

    OstTraceFunctionExit1(DUP1_CPWPA2UI_TRYUPDATE_EXIT,this);
    return true;
}

/*!
    Handles failed CommsDat update.
 */
void CpWpa2Ui::handleUpdateError()
{
    OstTraceFunctionEntry1(CPWPA2UI_HANDLEUPDATEERROR_ENTRY,this);
    
    // Show error note to user
    showMessageBox(
        HbMessageBox::MessageTypeWarning,
        hbTrId("txt_occ_info_unable_to_save_setting"));
    // Reload settings from CommsDat and update UI
    try {
        mCmCM->refresh();
    }
    catch (const std::exception&) {
        // Ignore error from refresh. Most likely this will not happen, but
        // if it does, there isn't very much we can do.
        OstTrace0(
            TRACE_ERROR,
            CPWPA2UI_HANDLEUPDATEERROR,
            "Refresh failed");
    };
    updateWpaSettings();
    
    OstTraceFunctionExit1(CPWPA2UI_HANDLEUPDATEERROR_EXIT,this);
}

/*!
    Shows message box with "OK" button using given text.
*/
void CpWpa2Ui::showMessageBox(
    HbMessageBox::MessageBoxType type,
    const QString &text)
{
    OstTraceFunctionEntry1(CPWPA2UI_SHOWMESSAGEBOX_ENTRY,this);
    
    // Create a message box
    mMessageBox = QSharedPointer<HbMessageBox>(new HbMessageBox(type));
    mMessageBox->setText(text);
    mMessageBox->open();
    
    OstTraceFunctionExit1(CPWPA2UI_SHOWMESSAGEBOX_EXIT,this);
}


void CpWpa2Ui::updateWpaSettings()
    {
    OstTraceFunctionEntry1(CPWPA2UI_UPDATEWPASETTINGS_ENTRY,this);
    mWpa2Ui->reset();
    OstTraceFunctionExit1(CPWPA2UI_UPDATEWPASETTINGS_EXIT,this);
    }

Q_EXPORT_PLUGIN2(CpWpa2Ui, CpWpa2Ui)
;
