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
 * %version: 22 %
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
#include <HbTranslator>
#include <HbEditorInterface>

//Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwepuiTraces.h"
#endif

// Constants
//The order in which WEP only mode appears in the list of available 
//security mode
static const int UI_ORDER_WEP = 10;

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



/*!
 \class CpWepUi
 \brief CpWepUi implements the WEP Security Settings Control Panel Plugin
 which will allow viewing/editing of WEP Security Settings.
 */
//Contructs WEP object
CpWepUi::CpWepUi() :
    mUi(NULL),
    mNewKeySelected(0), 
    mTranslator(new HbTranslator("cpwlansecsettingsplugin")),
    mCmCM(NULL), 
    mCmId(0)    
{
    //Initialize array members
    for(int index=0;index<KMaxNumberofKeys;index++)
    {
        mWepKey[index] = NULL;
        mWepKeyText[index] = NULL;   
        mkeyFormat[index] = EFormatHex;
    }
      
}

//Deletes all objects WEP owns
CpWepUi::~CpWepUi()
{
    OstTraceFunctionEntry1(CPWEPUI_CPWEPUI_ENTRY,this);
    //Elements like mUi and components that belong to it
    //, are taken care by the parent
    delete mTranslator;
    OstTraceFunctionExit1(CPWEPUI_CPWEPUI_EXIT,this);
}

// ======== MEMBER FUNCTIONS ========


/*!
 Getter for security mode.

 \return Security mode identifier
 */
CMManagerShim::WlanSecMode CpWepUi::securityMode() const
{
    OstTraceFunctionEntry1(CPWEPUI_SECURITYMODE_ENTRY,this);
    OstTraceFunctionExit1(CPWEPUI_SECURITYMODE_EXIT,this);
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
    OstTraceFunctionEntry1( CPWEPUI_SECURITYMODETEXTID_ENTRY, this );
    OstTraceFunctionExit1( CPWEPUI_SECURITYMODETEXTID_EXIT, this );
    return "txt_occ_setlabel_wlan_security_mode_val_wep";
}

/*! 
 Sets the database reference Iap id.

 \param id Database reference
 */
void CpWepUi::setReference(CmConnectionMethodShim *cmCm, uint id)
{
    OstTraceFunctionEntry1(CPWEPUI_SETREFERENCE_ENTRY,this);
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
 * \param dataHelper to add Connections
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
    
    //Store the address of the Data Helper
    mItemDataHelper = &dataHelpper;

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

    //Create Ui for all 4 WEP keys
    createWEPKeyGroup(KFirstKey);

    createWEPKeyGroup(KSecondKey);

    createWEPKeyGroup(KThirdKey);

    createWEPKeyGroup(KFourthKey);
    
    //Add Connections(signals)
    addConnections(dataHelpper);

    OstTraceFunctionExit1(CPWEPUI_UIINSTANCE_EXIT,this);
    return mUi;
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
 * Create Ui element with text edit for WEP KEYS
 * 
 * \param index of the WEP key
 * */
void CpWepUi::createWEPKeyGroup(int index)
    {
    OstTraceFunctionEntry1(CPWEPUI_CREATEWEPKEYGROUP_ENTRY,this);
    QString textId;
    
    switch(index)
        {
        case KFirstKey:
            textId  = hbTrId("txt_occ_subhead_wep_key_1");
            break;
            
            
        case KSecondKey:
            textId  = hbTrId("txt_occ_subhead_wep_key_2");
            break;
            
        case KThirdKey:
            textId  = hbTrId("txt_occ_subhead_wep_key_3");
            break;
            
        case KFourthKey:
            textId  = hbTrId("txt_occ_subhead_wep_key_4");
            break;
        }
        
   
    mWepKeyText[index] = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem,
            textId, mUi);

    if (mKeyData[index].length() != 0) {
        mWepKeyText[index]->setContentWidgetData("text",
                mKeyData[index]);
    }
    mWepKeyText[index]->setContentWidgetData("echoMode",HbLineEdit::PasswordEchoOnEdit);
    mWepKeyText[index]->setContentWidgetData("smileysEnabled", "false");

    
    mUi->appendChild(mWepKeyText[index]);
    OstTraceFunctionExit1(CPWEPUI_CREATEWEPKEYGROUP_EXIT,this);
    }


/*!
 * Add signals to all the text Edit of WEP key groups.
 *  
 *  \param dataHelper ; to add Connections
 */
void CpWepUi::addConnections(CpItemDataHelper &dataHelpper)
    {
    OstTraceFunctionEntry1( CPWEPUI_ADDCONNECTIONS_ENTRY, this );
    
    dataHelpper.addConnection(mWepKeyText[KFirstKey],
                SIGNAL( editingFinished ()), this, SLOT(wepKeyOneChanged() ));
    
    dataHelpper.addConnection(mWepKeyText[KSecondKey],
               SIGNAL( editingFinished ()), this, SLOT(wepKeyTwoChanged() ));
    
    dataHelpper.addConnection(mWepKeyText[KThirdKey],
               SIGNAL( editingFinished ()), this, SLOT(wepKeyThreeChanged() ));
    
    dataHelpper.addConnection(mWepKeyText[KFourthKey],
                SIGNAL( editingFinished ()), this, SLOT(wepKeyFourChanged() ));
    
    dataHelpper.connectToForm(SIGNAL(itemShown (const QModelIndex &) ), 
            this, SLOT(setEditorPreferences(const QModelIndex &)));
 
    OstTraceFunctionExit1( CPWEPUI_ADDCONNECTIONS_EXIT, this );
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
    
    //Store the wep key in use
    mNewKeySelected = wepKeyInUse;
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
        OstTrace0( TRACE_ERROR, CPWEPUI_WEPKEYTEXTCHANGED_ERROR, "CpWepUi::wepKeyTextChanged Invalid WEP Key Input" );        
        showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
                "txt_occ_info_invalid_input"));
    }
    OstTraceFunctionExit1(CPWEPUI_WEPKEYTEXTCHANGED_EXIT,this);
}

/*!
 * Slot that configures the editor settings for all WEP key fields.
 * This slot is invoked whenever a new item(s) are shown in the current view 
 * 
 * \param modelIndex Index of the current item in the  model
 */
void CpWepUi::setEditorPreferences(const QModelIndex &modelIndex)
{
    
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

    mKeyData.insert(KSecondKey,mCmCM->getString8Attribute(
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
