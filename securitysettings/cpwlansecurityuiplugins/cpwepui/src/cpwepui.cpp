/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
 *    Control Panel QT UI for WEP configuration
 *
 */

/*
 * %version: tr1cfwln#28 %
 */


//User Includes
#include "cpwepui.h"
#include "wepkeyvalidator.h"

// System includes
#include <QStringList>
#include <cpitemdatahelper.h>
#include <cmconnectionmethod_shim.h>
#include <cmmanagerdefines_shim.h>
#include <HbLineEdit>
#include <HbEditorInterface>

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwepuiTraces.h"
#endif

/*!
 \class CpWepUi
 \brief CpWepUi implements the WEP Security Settings Control Panel Plugin
 which will allow viewing/editing of WEP Security Settings.
 */

// External function prototypes

// Local constants

//! Index of first WEP key
static const int KFirstKey = 0;

//! Index of second WEP key
static const int KSecondKey = 1;

//! Index of third WEP key
static const int KThirdKey = 2;

//! Index of fourth WEP key
static const int KFourthKey = 3;

//!Maximum allowed length for WEP keys, in hex mode
static const int KMaxKeyLength  = 26;



// ======== LOCAL FUNCTIONS ========


// ======== MEMBER FUNCTIONS ========

/*!
 Contructs WEP object
 */
CpWepUi::CpWepUi(
    CpItemDataHelper* dataHelper,
    CmConnectionMethodShim* cmCM) :
    CpSettingFormItemData(
        HbDataFormModelItem::GroupItem,
        hbTrId("txt_occ_subhead_security_settings")),
    mNewKeySelected(0), 
    mCmCM(cmCM),
    mItemDataHelper(dataHelper)
{
    OstTraceExt1( TRACE_FLOW, CPWEPUI_CPWEPUI, "CpWepUi::CpWepUi - entry;cmCM=%p", cmCM );
    
    //Initialize array members
    for(int index=0;index<KMaxNumberofKeys;index++) {
        mWepKey[index] = NULL;
        mWepKeyText[index] = NULL;   
        mkeyFormat[index] = EFormatHex;
    }
    
    createUi();
    
    OstTraceExt1( TRACE_FLOW, DUP1_CPWEPUI_CPWEPUI, "CpWepUi::CpWepUi - exit;this=%p", this );
}

/*!
 Deletes all objects WEP owns
 */
CpWepUi::~CpWepUi()
{
    OstTraceExt1( TRACE_FLOW, DUP2_CPWEPUI_CPWEPUI, "CpWepUi::~CpWepUi - entry;this=%p", this );
    OstTrace0( TRACE_FLOW, DUP3_CPWEPUI_CPWEPUI, "CpWepUi::~CpWepUi - exit" );
}

/*!
 Returns the fully constructed Ui Group , for WEP security plugin
 */
void CpWepUi::createUi()
{
    int err;

    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_CREATEUI, "CpWepUi::createUi - entry" );   
    
    //Read values From CommsDatbase
    QT_TRYCATCH_ERROR(err, loadFieldsFromDataBase());
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWEPUI_CREATEUI, "CpWepUi::createUi - [ERROR]: loadFromDataBase failed;err=%d", err );   
    }

    setContentWidgetData("objectName", "CpWepUi");
    
    CpSettingFormItemData *wepKeyInUse = new CpSettingFormItemData(
        HbDataFormModelItem::ComboBoxItem, hbTrId(
            "txt_occ_setlabel_wep_key_in_use"));
    QStringList wepKeys;
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_1"));
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_2"));
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_3"));
    wepKeys.append(hbTrId("txt_occ_setlabel_wep_key_in_val_4"));

    wepKeyInUse->setContentWidgetData("items", wepKeys);
    wepKeyInUse->setContentWidgetData("currentIndex", mNewKeySelected);
    wepKeyInUse->setContentWidgetData("objectName", "CpWepUiKeyInUse");
    
    mItemDataHelper->addConnection(wepKeyInUse, SIGNAL(currentIndexChanged(int)),
        this, SLOT(wepKeyInUseChanged(int)));
    appendChild(wepKeyInUse);

    //Create Ui for all 4 WEP keys
    createWEPKeyGroup(KFirstKey);

    createWEPKeyGroup(KSecondKey);

    createWEPKeyGroup(KThirdKey);

    createWEPKeyGroup(KFourthKey);
    
    //Add Connections(signals)
    addConnections(mItemDataHelper);

    OstTrace0( TRACE_FLOW, DUP2_CPWEPUI_CREATEUI, "CpWepUi::createUi - exit" );
}

/*!
   Validates current security settings. This function is called whenever
   user tries to exit from the settings view. If the plugin determines
   that some settings need editing before considered valid, it shall
   return false. A dialog will be shown to the user indicating that
   settings are still incomplete and asking if he/she wishes to exit
   anyway.

   \return True if security settings for WEP are valid, false if not.
*/
bool CpWepUi::validateSettings()
{
    bool ret(false);
    //Check the latest string entered for the WEP key in the text box
    QVariant keyValue = mWepKeyText[mNewKeySelected]->contentWidgetData("text");
    QString keyString = keyValue.toString();
    
    WepKeyValidator::KeyStatus keystatus = WepKeyValidator::validateWepKey(keyString);
    
    //Check if key is  valid and not of zero length 
    if(keystatus==WepKeyValidator::KeyStatusOk) {
        ret = true;
    }
    return ret;
}

/*!
 Create Ui element with text edit for WEP KEYS
  
 \param index of the WEP key
 */
void CpWepUi::createWEPKeyGroup(int index)
{
    QString textId;
    
    OstTrace1( TRACE_FLOW, CPWEPUI_CREATEWEPKEYGROUP, "CpWepUi::createWEPKeyGroup - entry;index=%d", index );
    
    switch(index) {
        case KFirstKey:
            textId  = hbTrId("txt_occ_setlabel_wep_key_1");
            break;
            
        case KSecondKey:
            textId  = hbTrId("txt_occ_setlabel_wep_key_2");
            break;
            
        case KThirdKey:
            textId  = hbTrId("txt_occ_setlabel_wep_key_3");
            break;
            
        case KFourthKey:
            textId  = hbTrId("txt_occ_setlabel_wep_key_4");
            break;
    }
        
    mWepKeyText[index] = new CpSettingFormItemData(
        HbDataFormModelItem::TextItem,
        textId);
    

    if (mKeyData[index].length() != 0) {
        mWepKeyText[index]->setContentWidgetData("text", mKeyData[index]);
    }
    mWepKeyText[index]->setContentWidgetData("echoMode",HbLineEdit::PasswordEchoOnEdit);
    mWepKeyText[index]->setContentWidgetData("smileysEnabled", "false");
    QString objectName;
    objectName.setNum(index);
    objectName.prepend("CpWepUiKeyEditor");
    mWepKeyText[index]->setContentWidgetData("objectName", objectName);
    
    appendChild(mWepKeyText[index]);
    
    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_CREATEWEPKEYGROUP, "CpWepUi::createWEPKeyGroup - exit" );
}


/*!
 Add signals to all the text Edit of WEP key groups.
   
 \param dataHelper ; to add Connections
 */
void CpWepUi::addConnections(CpItemDataHelper* dataHelper)
{
    OstTrace0( TRACE_FLOW, CPWEPUI_ADDCONNECTIONS, "CpWepUi::addConnections - entry" );
    
    dataHelper->addConnection(mWepKeyText[KFirstKey],
        SIGNAL( editingFinished ()), this, SLOT(wepKeyOneChanged() ));
    
    dataHelper->addConnection(mWepKeyText[KSecondKey],
        SIGNAL( editingFinished ()), this, SLOT(wepKeyTwoChanged() ));
    
    dataHelper->addConnection(mWepKeyText[KThirdKey],
        SIGNAL( editingFinished ()), this, SLOT(wepKeyThreeChanged() ));
    
    dataHelper->addConnection(mWepKeyText[KFourthKey],
        SIGNAL( editingFinished ()), this, SLOT(wepKeyFourChanged() ));
    
    dataHelper->connectToForm(SIGNAL(itemShown (const QModelIndex &) ), 
        this, SLOT(setEditorPreferences(const QModelIndex &)));
    
    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_ADDCONNECTIONS, "CpWepUi::addConnections - exit" );   
}

/*!
 General method for handling WEP key string change
  
 \param index of the WEP key that changed
 */
void CpWepUi::wepKeyTextChanged(int index)
{
    OstTrace1( TRACE_FLOW, DUP1_CPWEPUI_WEPKEYTEXTCHANGED, "CpWepUi::wepKeyTextChanged - entry;index=%d", index );
    
    QVariant value = mWepKeyText[index]->contentWidgetData("text");
    QString key = value.toString();

    WepKeyValidator::KeyStatus keystatus = WepKeyValidator::validateWepKey(key);

    // allow storing an empty key to enable clearing WEP keys
    if (keystatus == WepKeyValidator::KeyStatusOk || key.length() == 0) {
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
    } else {
        OstTrace0( TRACE_ERROR, CPWEPUI_WEPKEYTEXTCHANGED, "CpWepUi::wepKeyTextChanged - [ERROR]: invalid WEP key input" );
        
        showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
                "txt_occ_info_invalid_input"));
    }
    
    OstTrace0( TRACE_FLOW, DUP2_CPWEPUI_WEPKEYTEXTCHANGED, "CpWepUi::wepKeyTextChanged - exit" ); 
}

/*!
 Store the WEP key in Comms
 
 \param enumValue the right field represented by the enum value
 \param key the WEP key String to store
 */
void CpWepUi::storeWEPKey(CMManagerShim::ConnectionMethodAttribute enumValue,
        QString& key)
{
    OstTrace1( TRACE_FLOW, CPWEPUI_STOREWEPKEY, "CpWepUi::storeWEPKey - entry;enumValue=%d", enumValue );
    
    mCmCM->setString8Attribute(enumValue, key);
    tryUpdate();
    
    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_STOREWEPKEY, "CpWepUi::storeWEPKey - exit" );
}

/*!
 Set the WEP key format
 
 \param key string to identify format
 \param index of the WEP key
 */
void CpWepUi::setKeyFormat(QString& key, int index)
{
    OstTrace1( TRACE_FLOW, CPWEPUI_SETKEYFORMAT, "CpWepUi::setKeyFormat - entry;index=%d", index );
    
    if (key.length() == WepKeyValidator::WepHex64BitMaxLength ||
        key.length() == WepKeyValidator::WepHex128BitMaxLength) {
        OstTrace0( TRACE_FLOW, DUP2_CPWEPUI_SETKEYFORMAT, "CpWepUi::setKeyFormat - format HEX" );
        mkeyFormat[index] = EFormatHex;
    } else if (key.length() == WepKeyValidator::WepAscii64BitMaxLength ||
               key.length() == WepKeyValidator::WepAscii128BitMaxLength) {
        OstTrace0( TRACE_FLOW, DUP3_CPWEPUI_SETKEYFORMAT, "CpWepUi::setKeyFormat - format ASCII" );
        mkeyFormat[index] = EFormatAscii;
    }
    
    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_SETKEYFORMAT, "CpWepUi::setKeyFormat - exit" );
}

/*!Get the right field in DB
 
 \param index of the WEP key
 */
CMManagerShim::ConnectionMethodAttribute CpWepUi::getWEPKeyEnum(int index)
{
    OstTrace1( TRACE_FLOW, CPWEPUI_GETWEPKEYENUM, "CpWepUi::getWEPKeyEnum - entry;index=%d", index );
    
    CMManagerShim::ConnectionMethodAttribute keyenum(
            CMManagerShim::WlanWepKey1InHex);

    switch (index) {
        case KFirstKey:
        {
            if (mkeyFormat[index] == EFormatHex) {
                keyenum = CMManagerShim::WlanWepKey1InHex;
            } else {
                keyenum = CMManagerShim::WlanWepKey1InAscii;
            }
        }
            break;

        case KSecondKey:
        {
            if (mkeyFormat[index] == EFormatHex) {
                keyenum = CMManagerShim::WlanWepKey2InHex;
            } else {
                keyenum = CMManagerShim::WlanWepKey2InAscii;
            }
        }
            break;

        case KThirdKey:
        {
            if (mkeyFormat[index] == EFormatHex) {
                keyenum = CMManagerShim::WlanWepKey3InHex;
            } else {
                keyenum = CMManagerShim::WlanWepKey3InAscii;
            }
        }
            break;

        case KFourthKey:
        {
            if (mkeyFormat[index] == EFormatHex) {
                keyenum = CMManagerShim::WlanWepKey4InHex;
            } else {
                keyenum = CMManagerShim::WlanWepKey4InAscii;
            }
        }
            break;

        default:
            break;
    }
    
    OstTrace1( TRACE_FLOW, DUP1_CPWEPUI_GETWEPKEYENUM, "CpWepUi::getWEPKeyEnum - exit;keyenum=%d", keyenum );
    
    return keyenum;
}

/*!
 Read all security settings from the Comms 
 */
void CpWepUi::loadFieldsFromDataBase()
{
    OstTrace0( TRACE_FLOW, CPWEPUI_LOADFIELDSFROMDATABASE, "CpWepUi::loadFieldsFromDataBase - entry" );
    
    //Wep Key in Use 
    mNewKeySelected = mCmCM->getIntAttribute(CMManagerShim::WlanWepKeyIndex);

    //All data fetched in Hex Format
    mKeyData.insert(KFirstKey, mCmCM->getString8Attribute(
        CMManagerShim::WlanWepKey1InHex));

    OstTrace0( TRACE_FLOW, DUP2_CPWEPUI_LOADFIELDSFROMDATABASE, "CpWepUi::loadFieldsFromDataBase - 1st key fetched" );
     
    mKeyData.insert(KSecondKey,mCmCM->getString8Attribute(
        CMManagerShim::WlanWepKey2InHex));

    OstTrace0( TRACE_FLOW, DUP3_CPWEPUI_LOADFIELDSFROMDATABASE, "CpWepUi::loadFieldsFromDataBase - 2nd key fetched" );
    
    mKeyData.insert(KThirdKey, mCmCM->getString8Attribute(
        CMManagerShim::WlanWepKey3InHex));

    OstTrace0( TRACE_FLOW, DUP4_CPWEPUI_LOADFIELDSFROMDATABASE, "CpWepUi::loadFieldsFromDataBase - 3rd key fetched" );
    
    mKeyData.insert(KFourthKey, mCmCM->getString8Attribute(
        CMManagerShim::WlanWepKey4InHex));

    OstTrace0( TRACE_FLOW, DUP5_CPWEPUI_LOADFIELDSFROMDATABASE, "CpWepUi::loadFieldsFromDataBase - 4th key fetched" );
    
    /*Set all key formats to Hex by default; because all keys are read in Hex from DB*/
    for (int count = 0; count < KMaxNumberofKeys; count++) {
        mkeyFormat[count] = EFormatHex;
    }

    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_LOADFIELDSFROMDATABASE, "CpWepUi::loadFieldsFromDataBase - exit" );
}

/*!
 Tries to update connection method changes to CommsDat.
 Returns "true" if success, "false" if some error happened. 
 */
bool CpWepUi::tryUpdate()
{
    OstTrace0( TRACE_FLOW, CPWEPUI_TRYUPDATE, "CpWepUi::tryUpdate - entry" );
    
    bool ret(true);
    // Try update
    try {
        mCmCM->update();
    }
    catch (const std::exception&) {
        OstTrace0( TRACE_ERROR, DUP2_CPWEPUI_TRYUPDATE, "CpWepUi::tryUpdate - [ERROR]: updating settings into database failed" );
        
        // Handle error
        handleUpdateError();
        ret = false;
    }

    OstTrace1( TRACE_FLOW, DUP1_CPWEPUI_TRYUPDATE, "CpWepUi::tryUpdate - exit;ret=%d", ret );
    
    return ret;
}

/*!
 Handles failed CommsDat update.
 */
void CpWepUi::handleUpdateError()
{
    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_HANDLEUPDATEERROR, "CpWepUi::handleUpdateError - entry" );
    
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
        OstTrace0( TRACE_ERROR, CPWEPUI_HANDLEUPDATEERROR, "CpWepUi::handleUpdateError - [ERROR]: refreshing settings from database failed" );
    }
    
    updateWepSettings();

    OstTrace0( TRACE_FLOW, DUP2_CPWEPUI_HANDLEUPDATEERROR, "CpWepUi::handleUpdateError - exit" );
}

/*!
 Shows message box with "OK" button using given text.
 */
void CpWepUi::showMessageBox(HbMessageBox::MessageBoxType type,
        const QString &text)
{
    OstTrace0( TRACE_FLOW, CPWEPUI_SHOWMESSAGEBOX, "CpWepUi::showMessageBox - entry" );
    
    // Create a message box
    mMessageBox = QSharedPointer<HbMessageBox> (new HbMessageBox(type));
    mMessageBox->setObjectName("CpWepUiMessageBox");
    mMessageBox->setText(text);
    mMessageBox->open();

    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_SHOWMESSAGEBOX, "CpWepUi::showMessageBox - exit" );
}

/*!
 * Reset the Key Items on the Ui, by reading the previously set value from Comms
 */
void CpWepUi::updateWepSettings()
{
    OstTrace0( TRACE_FLOW, CPWEPUI_UPDATEWEPSETTINGS, "CpWepUi::updateWepSettings - entry" );
    
    //Read values from Comms and update the Ui items; 
    loadFieldsFromDataBase();

    mWepKeyText[KFirstKey]->setContentWidgetData("text", mKeyData[KFirstKey]);

    mWepKeyText[KSecondKey]->setContentWidgetData("text",
        mKeyData[KSecondKey]);

    mWepKeyText[KThirdKey]->setContentWidgetData("text", mKeyData[KThirdKey]);

    mWepKeyText[KFourthKey]->setContentWidgetData("text",
        mKeyData[KFourthKey]);

    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_UPDATEWEPSETTINGS, "CpWepUi::updateWepSettings - exit" );
}

/*!
 Commit all WEP keys , except the one which was just set
  
 \param index ; the index of the key that was just set
 */
void CpWepUi::commitWEPkeys(int index)
{
    OstTrace0( TRACE_FLOW, CPWEPUI_COMMITWEPKEYS, "CpWepUi::commitWEPkeys - entry" );
    
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

    OstTrace0( TRACE_FLOW, DUP1_CPWEPUI_COMMITWEPKEYS, "CpWepUi::commitWEPkeys - exit" );
}

/*!
 Slot to handle , if a different wep key (index) 
 is made active
 
 \param wepKeyInUse index of the chosen wep key
 */
void CpWepUi::wepKeyInUseChanged(int wepKeyInUse)
{
    OstTrace1( TRACE_BORDER, CPWEPUI_WEPKEYINUSECHANGED, "CpWepUi::wepKeyInUseChanged - entry [SLOT];wepKeyInUse=%d", wepKeyInUse );
    
    int err;
    //Update CommsDat
    QT_TRYCATCH_ERROR(err, mCmCM->setIntAttribute(CMManagerShim::WlanWepKeyIndex, wepKeyInUse));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, DUP1_CPWEPUI_WEPKEYINUSECHANGED, "CpWepUi::wepKeyInUseChanged - [ERROR]: writing settings to database failed;err=%d", err );
    }
    tryUpdate();
    
    //Store the wep key in use
    mNewKeySelected = wepKeyInUse;
    
    OstTrace0( TRACE_BORDER, DUP2_CPWEPUI_WEPKEYINUSECHANGED, "CpWepUi::wepKeyInUseChanged - exit [SLOT]" );
}

/*!
 Slot for handling WEP key one string changes 
 */
void CpWepUi::wepKeyOneChanged()
{
    OstTrace0( TRACE_BORDER, CPWEPUI_WEPKEYONECHANGED, "CpWepUi::wepKeyOneChanged - entry [SLOT]" );
    
    int err;
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KFirstKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, DUP1_CPWEPUI_WEPKEYONECHANGED, "CpWepUi::wepKeyOneChanged - [ERROR]: wepKeyTextChanged failed;err=%d", err );        
    }
    
    OstTrace0( TRACE_BORDER, DUP2_CPWEPUI_WEPKEYONECHANGED, "CpWepUi::wepKeyOneChanged - exit [SLOT]" );
}

/*!
 Slot for handling WEP key two string changes 
 */
void CpWepUi::wepKeyTwoChanged()
{
    OstTrace0( TRACE_BORDER, CPWEPUI_WEPKEYTWOCHANGED, "CpWepUi::wepKeyTwoChanged - entry [SLOT]" );
    
    int err;
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KSecondKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, DUP1_CPWEPUI_WEPKEYTWOCHANGED, "CpWepUi::wepKeyTwoChanged - [ERROR]: wepKeyTextChanged failed;err=%d", err );
    }
    
    OstTrace0( TRACE_BORDER, DUP2_CPWEPUI_WEPKEYTWOCHANGED, "CpWepUi::wepKeyTwoChanged - exit [SLOT]" );
}

/*!
 Slot for handling WEP key three string changes 
 */
void CpWepUi::wepKeyThreeChanged()
{
    OstTrace0( TRACE_BORDER, CPWEPUI_WEPKEYTHREECHANGED, "CpWepUi::wepKeyThreeChanged - entry [SLOT]" );
    
    int err;
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KThirdKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, DUP1_CPWEPUI_WEPKEYTHREECHANGED, "CpWepUi::wepKeyThreeChanged - [ERROR]: wepKeyTextChanged failed;err=%d", err );
    }
    
    OstTrace0( TRACE_BORDER, DUP2_CPWEPUI_WEPKEYTHREECHANGED, "CpWepUi::wepKeyThreeChanged - exit [SLOT]" );
}

/*!
 Slot for handling WEP key four string changes 
 */
void CpWepUi::wepKeyFourChanged()
{
    OstTrace0( TRACE_BORDER, DUP1_CPWEPUI_WEPKEYFOURCHANGED, "CpWepUi::wepKeyFourChanged - entry [SLOT]" );
    
    int err;
    QT_TRYCATCH_ERROR(err, wepKeyTextChanged(KFourthKey));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWEPUI_WEPKEYFOURCHANGED, "CpWepUi::wepKeyFourChanged - [ERROR]: wepKeyTextChanged failed;err=%d", err );    
    }
    
    OstTrace0( TRACE_BORDER, DUP2_CPWEPUI_WEPKEYFOURCHANGED, "CpWepUi::wepKeyFourChanged - exit [SLOT]" );
}


/*!
 Slot that configures the editor settings for all WEP key fields.
 This method is invoken whenever a new item(s) are shown in the current view 
  
 \param modelIndex Index of the current item in the  model
 */
void CpWepUi::setEditorPreferences(const QModelIndex &modelIndex)
{
    OstTrace0( TRACE_BORDER, CPWEPUI_SETEDITORPREFERENCES, "CpWepUi::setEditorPreferences - entry [SLOT]" );
    
    HbDataFormModelItem *item = mItemDataHelper->modelItemFromModelIndex(modelIndex);

    HbSmileyTheme smiley;
    /* Configure settings only for text fields*/
    if(item->type() == HbDataFormModelItem::TextItem) {
        HbLineEdit *edit = qobject_cast<HbLineEdit*>(mItemDataHelper->widgetFromModelIndex(modelIndex));           
        HbEditorInterface editInterface(edit);    
        editInterface.setInputConstraints(HbEditorConstraintLatinAlphabetOnly);
        edit->setInputMethodHints(Qt::ImhNoPredictiveText);    
        edit->setMaxLength(KMaxKeyLength);
    }
    
    OstTrace0( TRACE_BORDER, DUP1_CPWEPUI_SETEDITORPREFERENCES, "CpWepUi::setEditorPreferences - exit [SLOT]" );
}

