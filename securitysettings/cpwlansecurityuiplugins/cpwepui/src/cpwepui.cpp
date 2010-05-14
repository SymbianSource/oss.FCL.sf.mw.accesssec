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
 *    Control Panel QT UI for WEP configuration
 *
 */

/*
 * %version: 16 %
 */

//User Includes
#include "cpwepui.h"

// System includes
#include <QStringList>
#include <cpsettingformentryitemdata.h>
#include <cpitemdatahelper.h>
#include <HbDataForm> 
#include <HbDeviceNotificationDialog> 
#include <QLocale>
#include <QCoreApplication>
#include <cmconnectionmethod_shim.h>
#include <cmpluginwlandef.h>
#include <cmmanagerdefines_shim.h>

#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwepuiTraces.h"
#endif

// Constants
//The order in which WEP only mode appears in the list of available 
//security mode
static const int UI_ORDER_WEP = 10;

/*!
 \class CpWepUi
 \brief CpWepUi implements the WEP Security Settings Control Panel Plugin
 which will allow viewing/editing of WEP Security Settings.
 */
//Contructs WEP object
CpWepUi::CpWepUi() :
    mUi(NULL), mNewKeySelected(0), mTranslator(NULL), mCmCM(NULL), mCmId(0)
{
    mTranslator = new QTranslator(this);
    mTranslator->load(":/loc/wlan_en_GB.qm");
    qApp->installTranslator(mTranslator);

    /* Install localization
     mTranslator = QSharedPointer<HbTranslator> (
     new HbTranslator("wlan_en_GB"));*/
}

//Deletes all objects WEP owns
CpWepUi::~CpWepUi()
{
    OstTraceFunctionEntry1(CPWEPUI_CPWEPUI_ENTRY,this);
    //Elements like mUi and components that belong to it
    //, are taken care by the parent
    OstTraceFunctionExit1(CPWEPUI_CPWEPUI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========


/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWepUi::securityMode() const
{
    OstTraceFunctionEntry1(CPWEPUI_MODE_ENTRY,this);
    OstTraceFunctionExit1(CPWEPUI_MODE_EXIT,this);
    //return security mode
    return CMManagerShim::WlanSecModeWep;
}

/*!
 Getter for localization text identifier for the security mode,
 f.ex. "txt_occ_setlabel_wlan_security_mode_val_wep". This localized
 text will be shown in the UI.
 
 \return Localization text ID
 */
QString CpWepUi::securityModeTextId() const
{
    OstTraceFunctionEntry1(CPWEPUI_LOCALIZATION_ID_ENTRY,this);
    OstTraceFunctionExit1(CPWEPUI_LOCALIZATION_ID_EXIT,this);
    return "txt_occ_setlabel_wlan_security_mode_val_wep";
}

/*! 
 Sets the database reference (WLAN Service Table ID).

 \param id Database reference
 */
void CpWepUi::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceFunctionEntry1(CPWEPUI_SETREFERENCE_ENTRY,this);

    // Assuming that id is the connection method Id/IAP Id.
    //mCmId - Not used currently
    mCmId = id;

    //mCmCM is not deleted assuming CmManager owns it.
    mCmCM = cmCm;
    OstTraceFunctionExit1(CPWEPUI_SETREFERENCE_EXIT,this);
}

/*!
 Getter for order number. This order number is used by the client of
 this interface to put the security modes in correct order in the list.

 \return An order number
 */
int CpWepUi::orderNumber() const
{
    OstTraceFunctionEntry1(CPWEPUI_ORDERNUMBER_ENTRY,this);
    OstTraceFunctionExit1(CPWEPUI_ORDERNUMBER_EXIT,this);
    return UI_ORDER_WEP;
}

/*!
 * Returns the fully constructed Ui Group , for WEP security plugin
 * 
 * \param \param dataHelper to add Connections
 * 
 * \return The WEP UI
 */
CpSettingFormItemData* CpWepUi::uiInstance(CpItemDataHelper &dataHelpper)
{
    int err;
    OstTraceFunctionEntry1(CPWEPUI_UIINSTANCE_ENTRY,this);

    //Read values From CommsDatbase
    QT_TRYCATCH_ERROR(err, loadFieldsFromDataBase());
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWEPUI_UIINSTANCE, "LoadFromDataBase returned %d", err );
    }

    mUi = new CpSettingFormItemData(HbDataFormModelItem::GroupItem, hbTrId(
            "txt_occ_subhead_security_settings"));

    CpSettingFormItemData *wepKeyInUse = new CpSettingFormItemData(
            HbDataFormModelItem::ComboBoxItem, hbTrId(
                    "txt_occ_setlabel_wep_key_in_use"), mUi);
    QStringList wepKeys;
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_1"));
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_2"));
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_3"));
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_4"));

    wepKeyInUse->setContentWidgetData("items", wepKeys);
    wepKeyInUse->setContentWidgetData("currentIndex", mNewKeySelected);
    dataHelpper.addConnection(wepKeyInUse, SIGNAL(currentIndexChanged(int)),
            this, SLOT(wepKeyInUseChanged(int)));
    mUi->appendChild(wepKeyInUse);

    createWEPKeyOneGroup(dataHelpper);

    createWEPKeyTwoGroup(dataHelpper);

    createWEPKeyThreeGroup(dataHelpper);

    createWEPKeyFourGroup(dataHelpper);

    OstTraceFunctionExit1(CPWEPUI_UIINSTANCE_EXIT,this);
    return mUi;
}

/*!
 * Create Ui element with text edit for WEP KEY One
 * 
 * \param dataHelper to add Connections
 */
void CpWepUi::createWEPKeyOneGroup(CpItemDataHelper &dataHelpper)
    {
    OstTraceFunctionEntry1(CPWEPUI_CREATEWEPKEYONEGROUP_ENTRY,this);
    mWepKeyText[KFirstKey] = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem,
            hbTrId("txt_occ_subhead_wep_key_1"), mUi);

    if (mKeyData[KFirstKey].length() != 0) {
        mWepKeyText[KFirstKey]->setContentWidgetData("text",
                mKeyData[KFirstKey]);
    }
    mWepKeyText[KFirstKey]->setContentWidgetData("echoMode", 2);
    mWepKeyText[KFirstKey]->setContentWidgetData("smileysEnabled", "false");

    dataHelpper.addConnection(mWepKeyText[KFirstKey],
            SIGNAL( editingFinished ()), this, SLOT(wepKeyOneChanged() ));

    mUi->appendChild(mWepKeyText[KFirstKey]);
    OstTraceFunctionExit1(CPWEPUI_CREATEWEPKEYONEGROUP_EXIT,this);
    }

/*!
 * Create Ui element with text edit for WEP KEY Two
 * \param dataHelper to add Connections
 */
void CpWepUi::createWEPKeyTwoGroup(CpItemDataHelper &dataHelpper)
{
    OstTraceFunctionEntry1(CPWEPUI_CREATEWEPKEYTWOGROUP_ENTRY,this);
    mWepKeyText[KSecondKey] = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem,
            hbTrId("txt_occ_subhead_wep_key_2"), mUi);

    if (mKeyData[KSecondKey].length() != 0) {
        mWepKeyText[KSecondKey]->setContentWidgetData("text",
                mKeyData[KSecondKey]);
    }
    mWepKeyText[KSecondKey]->setContentWidgetData("echoMode", 2);
    mWepKeyText[KSecondKey]->setContentWidgetData("smileysEnabled", "false");
    dataHelpper.addConnection(mWepKeyText[KSecondKey],
            SIGNAL( editingFinished ()), this, SLOT(wepKeyTwoChanged() ));

    mUi->appendChild(mWepKeyText[KSecondKey]);
    OstTraceFunctionExit1(CPWEPUI_CREATEWEPKEYTWOGROUP_EXIT,this);
}

/*!
 * Create Ui element with text edit for WEP KEY Three
 * \param dataHelper to add Connections
 */
void CpWepUi::createWEPKeyThreeGroup(CpItemDataHelper &dataHelpper)
{
    OstTraceFunctionEntry1(CPWEPUI_CREATEWEPKEYTHREEGROUP_ENTRY,this);
    mWepKeyText[KThirdKey] = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem,
            hbTrId("txt_occ_subhead_wep_key_3"), mUi);

    if (mKeyData[KThirdKey].length() != 0) {
        mWepKeyText[KThirdKey]->setContentWidgetData("text",
                mKeyData[KThirdKey]);
    }
    mWepKeyText[KThirdKey]->setContentWidgetData("echoMode", 2);
    mWepKeyText[KThirdKey]->setContentWidgetData("smileysEnabled", "false");
    dataHelpper.addConnection(mWepKeyText[KThirdKey],
            SIGNAL( editingFinished ()), this, SLOT(wepKeyThreeChanged() ));

    mUi->appendChild(mWepKeyText[KThirdKey]);
    OstTraceFunctionExit1(CPWEPUI_CREATEWEPKEYTHREEGROUP_EXIT,this);
}

/*!
 * Create Ui element with text edit for WEP KEY  Four
 * \param dataHelper to add Connections
 */
void CpWepUi::createWEPKeyFourGroup(CpItemDataHelper &dataHelpper)
{
    OstTraceFunctionEntry1(CPWEPUI_CREATEWEPKEYFOURGROUP_ENTRY,this);
    mWepKeyText[KFourthKey] = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem,
            hbTrId("txt_occ_subhead_wep_key_4"), mUi);

    if (mKeyData[KFourthKey].length() != 0) {
        mWepKeyText[KFourthKey]->setContentWidgetData("text",
                mKeyData[KFourthKey]);
    }
    mWepKeyText[KFourthKey]->setContentWidgetData("echoMode", 2);
    mWepKeyText[KFourthKey]->setContentWidgetData("smileysEnabled", "false");
    dataHelpper.addConnection(mWepKeyText[KFourthKey],
            SIGNAL( editingFinished ()), this, SLOT(wepKeyFourChanged() ));

    mUi->appendChild(mWepKeyText[KFourthKey]);
    OstTraceFunctionExit1(CPWEPUI_CREATEWEPKEYFOURGROUP_EXIT,this);
}

/*!
 * Slot to handle , if a different wep key (index) 
 * is made active
 * \param wepKeyInUse index of the chosen wep key
 */
void CpWepUi::wepKeyInUseChanged(int wepKeyInUse)
{
    OstTraceFunctionEntry1(CPWEPUI_WEPKEYINUSECHANGED_ENTRY,this);

    int err;
    //Update CommsDat
    QT_TRYCATCH_ERROR(err, mCmCM->setIntAttribute(CMManagerShim::WlanWepKeyIndex, wepKeyInUse));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWEPUI_WEPKEYINUSECHANGED, "Error wepKeyInUse returned %d", err );
    }
    tryUpdate();
    OstTraceFunctionExit1(CPWEPUI_WEPKEYINUSECHANGED_EXIT,this);
}

/*!
 * Slot to handle ,when the  
 *   wep key one string gets changed
 * 
 * 
 */
void CpWepUi::wepKeyOneChanged()
{
    int err;
    OstTraceFunctionEntry1(CPWEPUI_WEPKEY1STRINGCHANGED_ENTRY,this);
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KFirstKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR,CPWEPUI_WEPKEYONECHANGED, "Error wepKeyOneChanged returned %d", err );
        }
    OstTraceFunctionExit1(CPWEPUI_WEPKEY1STRINGCHANGED_EXIT,this);
}

/*!
 * Slot to handle ,when the  
 *   wep key two string gets changed
 * 
 * 
 */
void CpWepUi::wepKeyTwoChanged()
{
    int err;
    OstTraceFunctionEntry1(CPWEPUI_WEPKEY2STRINGCHANGED_ENTRY,this);
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KSecondKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWEPUI_WEPKEYTWOCHANGED, "Error wepKeyTwoChanged returned %d", err );
    }
    OstTraceFunctionExit1(CPWEPUI_WEPKEY2STRINGCHANGED_EXIT,this);
}

/*!
 * Slot to handle ,when the  
 *   wep key three string gets changed
 * 
 * 
 */
void CpWepUi::wepKeyThreeChanged()
{
    int err;
    OstTraceFunctionEntry1(CPWEPUI_WEPKEY3STRINGCHANGED_ENTRY,this);
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KThirdKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR,CPWEPUI_WEPKEYTHREECHANGED, "Error wepKeyThreeChanged returned %d", err );
    }
    OstTraceFunctionExit1(CPWEPUI_WEPKEY3STRINGCHANGED_EXIT,this);
}

/*!
 * Slot to handle ,when the  
 *   wep key four string gets changed
 * 
 * 
 */
void CpWepUi::wepKeyFourChanged()
{
    int err;
    OstTraceFunctionEntry1(CPWEPUI_WEPKEY4STRINGCHANGED_ENTRY,this);
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KFourthKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWEPUI_WEPKEYFOURCHANGED, "Error wepKeyFourChanged returned %d", err );
    }OstTraceFunctionExit1(CPWEPUI_WEPKEY4STRINGCHANGED_EXIT,this);
}

/*!
 * Slot to handle change in either of the 4 WEP key strings
 * 
 * \param index of the WEP key that changed
 */
void CpWepUi::wepKeyTextChanged(int index)
{
    OstTraceFunctionEntry1(CPWEPUI_WEPKEYTEXTCHANGED_ENTRY,this);

    QVariant value = mWepKeyText[index]->contentWidgetData("text");

    WepKeyValidator::KeyStatus keystatus = WepKeyValidator::validateWepKey(
            value.toString());

    if (keystatus == WepKeyValidator::KeyStatusOk) {
        QString key = value.toString();

        //If key is valid set the format of the key
        setKeyFormat(key, index);

        //Get the right field to store
        CMManagerShim::ConnectionMethodAttribute keyEnum = getWEPKeyEnum(index);

        //Store the WEP key
        storeWEPKey(keyEnum, key);

        //Update the latest key into array
        mKeyData[index] = key;

        /*
         * Commit All 4 WEP keys , anyways
         */
        commitWEPkeys(index);
    }
    else {
        showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
                "txt_occ_info_invalid_input"));
    }
    OstTraceFunctionExit1(CPWEPUI_WEPKEYTEXTCHANGED_EXIT,this);
}

/*!
 * Store the WEP key in Comms
 * \enumValue the right field represented by the enum value
 * \key the WEP key String to store
 */
void CpWepUi::storeWEPKey(CMManagerShim::ConnectionMethodAttribute enumValue,
        QString& key)
{
    mCmCM->setString8Attribute(enumValue, key);
    tryUpdate();
}

/*!
 * Set the WEP key format
 * \key string to identify format
 * \index of the WEP key
 */
void CpWepUi::setKeyFormat(QString& key, int index)
{
    if (key.length() == WepKeyValidator::WepHex64BitMaxLength || key.length()
            == WepKeyValidator::WepHex128BitMaxLength) {
        mkeyFormat[index] = EFormatHex;
    }

    else if (key.length() == WepKeyValidator::WepAscii64BitMaxLength
            || key.length() == WepKeyValidator::WepAscii128BitMaxLength) {
        mkeyFormat[index] = EFormatAscii;
    }
}

/*!Get the right field in DB
 * \index of the WEP key
 */
CMManagerShim::ConnectionMethodAttribute CpWepUi::getWEPKeyEnum(int index)
{
    CMManagerShim::ConnectionMethodAttribute keyenum(
            CMManagerShim::WlanWepKey1InHex);
    switch (index)
        {
        case KFirstKey:
            {
                if (mkeyFormat[index] == EFormatHex) {
                    keyenum = CMManagerShim::WlanWepKey1InHex;
                }
                else {
                    keyenum = CMManagerShim::WlanWepKey1InAscii;
                }
            }
            break;

        case KSecondKey:
            {
                if (mkeyFormat[index] == EFormatHex) {
                    keyenum = CMManagerShim::WlanWepKey2InHex;
                }
                else {
                    keyenum = CMManagerShim::WlanWepKey2InAscii;
                }
            }
            break;

        case KThirdKey:
            {
                if (mkeyFormat[index] == EFormatHex) {
                    keyenum = CMManagerShim::WlanWepKey3InHex;
                }
                else {
                    keyenum = CMManagerShim::WlanWepKey3InAscii;
                }
            }
            break;

        case KFourthKey:
            {
                if (mkeyFormat[index] == EFormatHex) {
                    keyenum = CMManagerShim::WlanWepKey4InHex;
                }
                else {
                    keyenum = CMManagerShim::WlanWepKey4InAscii;
                }
            }
            break;

        default:
            break;
        }
    return keyenum;
}
/*
 * Read all security settings from the Comms 
 */
void CpWepUi::loadFieldsFromDataBase()
{
    OstTraceFunctionEntry1(CPWEPUI_LOADFIELDSFROMDATABASE_ENTRY,this);

    //Wep Key in Use 
    mNewKeySelected = mCmCM->getIntAttribute(CMManagerShim::WlanWepKeyIndex);

    //All data fetched in Hex Format
    mKeyData.insert(KFirstKey, mCmCM->getString8Attribute(
            CMManagerShim::WlanWepKey1InHex));

    mKeyData.insert(KSecondKey, mCmCM->getString8Attribute(
            CMManagerShim::WlanWepKey2InHex));

    mKeyData.insert(KThirdKey, mCmCM->getString8Attribute(
            CMManagerShim::WlanWepKey3InHex));

    mKeyData.insert(KFourthKey, mCmCM->getString8Attribute(
            CMManagerShim::WlanWepKey4InHex));

    /*Set all key formats to Hex by default; because all keys are read in Hex from DB*/
    for (int count = 0; count < KMaxNumberofKeys; count++)
        {
        mkeyFormat[count] = EFormatHex;
        }

    OstTraceFunctionExit1(CPWEPUI_LOADFIELDSFROMDATABASE_EXIT,this);
}

/*!
 Tries to update connection method changes to CommsDat.
 Returns "true" if success, "false" if some error happened. 
 */
bool CpWepUi::tryUpdate()
{
    OstTraceFunctionEntry1(CPWEPUI_TRYUPDATE_ENTRY,this);

    bool ret(true);
    // Try update
    try {
        mCmCM->update();
    }
    catch (const std::exception&) {
        // Handle error
        handleUpdateError();
        ret = false;
    }

    OstTraceFunctionExit1(DUP1_CPWEPUI_TRYUPDATE_EXIT,this);
    return ret;
}

/*!
 Handles failed CommsDat update.
 */
void CpWepUi::handleUpdateError()
{
    OstTraceFunctionEntry1(CPWEPUI_HANDLEUPDATEERROR_ENTRY,this);

    // Show error note to user
    showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
            "txt_occ_info_unable_to_save_setting"));
    // Reload settings from CommsDat and update UI
    try {
        mCmCM->refresh();
    }
    catch (const std::exception&) {
        // Ignore error from refresh. Most likely this will not happen, but
        // if it does, there isn't very much we can do.
        OstTrace0(
                TRACE_ERROR,
                CPWEPPLUGIN_HANDLEUPDATEERROR,
                "Refresh failed");
    };
    updateWepSettings();

    OstTraceFunctionExit1(CPWEPUI_HANDLEUPDATEERROR_EXIT,this);
}

/*!
 Shows message box with "OK" button using given text.
 */
void CpWepUi::showMessageBox(HbMessageBox::MessageBoxType type,
        const QString &text)
{
    OstTraceFunctionEntry1(CPWEPUI_SHOWMESSAGEBOX_ENTRY,this);

    // Create a message box
    mMessageBox = QSharedPointer<HbMessageBox> (new HbMessageBox(type));
    mMessageBox->setText(text);
    mMessageBox->open();

    OstTraceFunctionExit1(CPWEPUI_SHOWMESSAGEBOX_EXIT,this);
}

/*!
 * Reset the Key Items on the Ui, by reading the previously set value from Comms
 */
void CpWepUi::updateWepSettings()
    {
    OstTraceFunctionEntry1(CPWEPUI_UPDATEWEPSETTINGS_ENTRY,this);
    //Read values from Comms and update the Ui items; 
    loadFieldsFromDataBase();

    mWepKeyText[KFirstKey]->setContentWidgetData("text", mKeyData[KFirstKey]);

    mWepKeyText[KSecondKey]->setContentWidgetData("text",
            mKeyData[KSecondKey]);

    mWepKeyText[KThirdKey]->setContentWidgetData("text", mKeyData[KThirdKey]);

    mWepKeyText[KFourthKey]->setContentWidgetData("text",
            mKeyData[KFourthKey]);

    OstTraceFunctionExit1(CPWEPUI_UPDATEWEPSETTINGS_EXIT,this);
    }

/*!
 * Commit all WEP keys , except the one which was just set
 * 
 * \param index ; the index of the key that was just set
 */
void CpWepUi::commitWEPkeys(int index)
    {
    OstTraceFunctionEntry1(CPWEPUI_COMMITWEPKEYS_ENTRY,this);
    //We have all data in Hex, so setting all WEP keys in hex

    if (index != KFirstKey) {
        //Get the right field to store
        CMManagerShim::ConnectionMethodAttribute keyEnumOne = getWEPKeyEnum(
                KFirstKey);

        //Store the WEP key
        storeWEPKey(keyEnumOne, mKeyData[KFirstKey]);
    }

    if (index != KSecondKey) {
        //Get the right field to store
        CMManagerShim::ConnectionMethodAttribute keyEnumTwo = getWEPKeyEnum(
                KSecondKey);

        //Store the WEP key
        storeWEPKey(keyEnumTwo, mKeyData[KSecondKey]);
    }

    if (index != KThirdKey) {
        //Get the right field to store
        CMManagerShim::ConnectionMethodAttribute keyEnumThree =
                getWEPKeyEnum(KThirdKey);

        //Store the WEP key
        storeWEPKey(keyEnumThree, mKeyData[KThirdKey]);
    }

    if (index != KFourthKey) {
        //Get the right field to store
        CMManagerShim::ConnectionMethodAttribute keyEnumFour = getWEPKeyEnum(
                KFourthKey);

        //Store the WEP key
        storeWEPKey(keyEnumFour, mKeyData[KFourthKey]);
    }

    OstTraceFunctionExit1(CPWEPUI_COMMITWEPKEYS_EXIT,this);
}

Q_EXPORT_PLUGIN2(CpWepUi, CpWepUi)
;
