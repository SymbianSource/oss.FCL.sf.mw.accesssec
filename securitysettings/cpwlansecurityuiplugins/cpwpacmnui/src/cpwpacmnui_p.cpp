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
 *    Private Implementation for Control Panel QT UI for WPA/WPA2/802_Dot_1x configuration
 *
 */

/*
 * %version: tr1cfwln#14 %
 */
 
// User Includes
#include "cpwpacmnui_p.h"
#include "wpakeyvalidator.h"
#include "cpwpacmneapui.h"

// System Includes
#include <QStringList>
#include <cpsettingformitemdata.h>
#include <cpitemdatahelper.h>
#include <cmconnectionmethod_shim.h>
#include <eapqtplugininfo.h>
#include <eapqtpluginhandle.h>
#include <eapqtconfiginterface.h>
#include <HbLineEdit>
#include <HbEditorInterface>

// Trace Definition
#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpacmnui_pTraces.h"
#endif


/*!
 \class CpWpaCmnUiPrivate
 \brief CpWpaCmnUiPrivate is a private class implementation the common Ui for WPA/WPA2/802.1x/WPA2 only 
 Security Settings Control Panel Plugins,
 which will allow viewing/editing of WPA/WPA2/802.1x/WPA2 Security Settings.
 */
/*!
 * Constructor Common Ui (WPA/WPA2/802.1x/WPA2only) object
 * 
 * \param securityMode chosen by user , for which Ui is constructed and returned
 * \param dataHelpper Control Panel Item data helpper object
 * \param commonUi Pointer To public class for CpWpaCmnUiPrivate
 */
CpWpaCmnUiPrivate::CpWpaCmnUiPrivate(CMManagerShim::WlanSecMode securityMode,
        CpItemDataHelper &dataHelpper) :
    mDataHelper(dataHelpper), 
    mCmnUi(NULL), 
    mPskKeyText(NULL), 
    mEapPlugins(NULL), 
    mUnencryptedConnection(NULL),
    mWpaEapItem(NULL),
    mEapEntry(NULL),
    mEapQtConfigInterface(NULL),  
    mSecurityMode(securityMode),
    mConnMethod(NULL),
    mEnablePskMode(true),
    mCurrentEapPlugin(0), 
    mUnencryptState(false)
{
    Q_ASSERT(
            mSecurityMode == CMManagerShim::WlanSecModeWpa ||
            mSecurityMode == CMManagerShim::WlanSecModeWpa2 ||
            mSecurityMode == CMManagerShim::WlanSecMode802_1x);
    OstTrace1( TRACE_FLOW, DUP1_CPWPACMNUIPRIVATE_CPWPACMNUIPRIVATE, "CpWpaCmnUiPrivate::CpWpaCmnUiPrivate;mSecurityMode=%u", mSecurityMode );
    
}

/*!
 * Destructor - Deletes objects owned by Common Ui
 */
CpWpaCmnUiPrivate::~CpWpaCmnUiPrivate()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CPWPACMNUIPRIVATE_ENTRY, this );
    //delete all dynamically allocated objects

    mCmnUi = NULL;
    mConnMethod = NULL;

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CPWPACMNUIPRIVATE_EXIT, this );
}

// ======== MEMBER FUNCTIONS ========

/*!
 * Creates the Ui instance based on the security mode;WPAWPA2/802.1x/WPA2 only 
 * Owns the Ui instance
 * 
 * \param eapQtConfigInterface to list all eap plugins
 * \param mCmCM Connection MethoD Qt interface
 * 
 * \return Ui instance for the security mode set
 */

CpSettingFormItemData* CpWpaCmnUiPrivate::createUi(
        EapQtConfigInterface *eapQtConfigInterface,
        CmConnectionMethodShim *cmCM)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CREATEUI_ENTRY, this );

    // NOT OWNED
    mConnMethod = cmCM;
    mEapQtConfigInterface = eapQtConfigInterface;
    mPlugins.append(mEapQtConfigInterface->supportedOuterTypes());
    qSort(mPlugins.begin(), mPlugins.end(), CpWpaCmnUiPrivate::pluginLessThan);

    mCmnUi = new CpSettingFormItemData(HbDataFormModelItem::GroupItem,
            hbTrId("txt_occ_subhead_security_settings"));

    mCmnUi->setContentWidgetData("objectName", "CpWpaCmUi");
    
    //LoadUi based on the security mode
    loadUi();

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CREATEUI_EXIT, this );
    return mCmnUi;
}

/*! 
 Load the CpSettingFormItemData components,for the
 EAP  mode
 */
CpBaseSettingView* CpWpaCmnUiPrivate::eapUiInstance()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_EAPUIINSTANCE_ENTRY, this );
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_EAPUIINSTANCE_EXIT, this );
    return mEapQtConfigInterface->uiInstance(EapQtPluginHandle::PluginUndefined,
            mPlugins.at(mCurrentEapPlugin).pluginHandle());
}



/*!
 * Creates Combo box for PSK and EAP mode selection.
 * 
 * @return CompoBox object.
 */
CpSettingFormItemData* CpWpaCmnUiPrivate::createWpaTypeSelector()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CREATEWPATYPESELECTOR_ENTRY, this );

    // In case of the object exists just update the data
    if (!mWpaEapItem) {
        mWpaEapItem = new CpSettingFormItemData(
            HbDataFormModelItem::ComboBoxItem, 
            hbTrId("txt_occ_setlabel_wpawpa2"));

        QStringList wpatype;
        wpatype.append(hbTrId("txt_occ_setlabel_wpawpa2_val_eap"));
        wpatype.append(hbTrId("txt_occ_setlabel_wpawpa2_val_preshared_key"));

        mWpaEapItem->setContentWidgetData("objectName", "CpWpaCmnUiTypeSelector");
        mWpaEapItem->setContentWidgetData("items", wpatype);

        mDataHelper.addConnection(mWpaEapItem,
            SIGNAL(currentIndexChanged(int)), this,
            SLOT(wpaTypeChanged(int)));

        mCmnUi->appendChild(mWpaEapItem);
    }

    mWpaEapItem->setContentWidgetData("currentIndex", mEnablePskMode ? 1 : 0);

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CREATEWPATYPESELECTOR_EXIT, this );
    return mWpaEapItem;
}

/*!
 * Creates LineEditor for WPA-PSK
 * 
 * @return LineEdit object.
 */
CpSettingFormItemData* CpWpaCmnUiPrivate::createPskEditor()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CREATEPSKEDITOR_ENTRY, this );

    if (!mPskKeyText) {
        mPskKeyText = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem, 
            hbTrId("txt_occ_setlabel_preshared_key"));

        mPskKeyText->setContentWidgetData("objectName", "CpWpaCmnUiPskEditor");
        mPskKeyText->setContentWidgetData("echoMode", HbLineEdit::PasswordEchoOnEdit);
        mPskKeyText->setContentWidgetData("smileysEnabled", "false");
        mDataHelper.addConnection(
            mPskKeyText, SIGNAL( editingFinished ()),
            this, SLOT(pskKeyChanged() ));
        
        mDataHelper.connectToForm(
            SIGNAL(itemShown (const QModelIndex &) ), 
            this, SLOT(setEditorPreferences(const QModelIndex &)));

        mCmnUi->appendChild(mPskKeyText);
    }

    mPskKeyText->setContentWidgetData("text", mKeyData);

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CREATEPSKEDITOR_EXIT, this );
    return mPskKeyText;
}

/*!
 * Creates Combo box for EAP outer type selection
 * 
 * @return CompoBox object.
 */
CpSettingFormItemData* CpWpaCmnUiPrivate::createEapSelector()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CREATEEAPSELECTOR_ENTRY, this );

    if (!mEapPlugins) {
        mEapPlugins = new CpSettingFormItemData(
            HbDataFormModelItem::ComboBoxItem, 
            hbTrId("txt_occ_setlabel_eap_type"));

        QStringList list;
        QList<EapQtPluginInfo>::iterator i;
        for (i = mPlugins.begin() ; i != mPlugins.end() ; ++i){
            list << i->localizationId();
        }
        
        mEapPlugins->setContentWidgetData("objectName", "CpWpaCmnUiEapTypeSelector");   
        mEapPlugins->setContentWidgetData("items", list);

        mDataHelper.addConnection(mEapPlugins,
            SIGNAL(currentIndexChanged(int)), this,
            SLOT(eapTypeChanged(int)));

        mCmnUi->appendChild(mEapPlugins);
    }

    mEapPlugins->setContentWidgetData("currentIndex", mCurrentEapPlugin);

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CREATEEAPSELECTOR_EXIT, this );
    return mEapPlugins;
}

/*!
 * Creates a button for EAP configurations
 * 
 * @return EntryItem for EAP
 */
EapEntryItemData* CpWpaCmnUiPrivate::createEapEntryItem()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CREATEEAPENTRYITEM_ENTRY, this );

    if (!mEapEntry) {
        mEapEntry = new EapEntryItemData(
            this, 
            mDataHelper, 
            hbTrId("txt_occ_button_eap_type_settings"));

        mEapEntry->setContentWidgetData("objectName", "CpWpaCmnUiEapEntryItem");
        mCmnUi->appendChild(mEapEntry);
    }

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CREATEEAPENTRYITEM_EXIT, this );
    return mEapEntry;
}

/*!
 * Creates Combo box for Unencrypted selection
 * 
 * @return CompoBox object.
 */
CpSettingFormItemData* CpWpaCmnUiPrivate::createUnencryptedBox()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_CREATEUNENCRYPTEDBOX_ENTRY, this );

    if (!mUnencryptedConnection) {
        mUnencryptedConnection = new CpSettingFormItemData(
            HbDataFormModelItem::CheckBoxItem, 
            hbTrId("txt_occ_setlabel_unencrypted_connection"));

        mUnencryptedConnection->setContentWidgetData(
            "objectName", 
            "CpWpaCmnUiUnencryptedConnection");
        mUnencryptedConnection->setContentWidgetData("text", hbTrId(
                "txt_occ_setlabel_unencrypted_connection_val_allowe"));

        mDataHelper.addConnection(mUnencryptedConnection,
                SIGNAL( stateChanged(int)), this,
                SLOT(unencryptConnStateChanged(int)));

        mCmnUi->appendChild(mUnencryptedConnection);
   }

    mUnencryptedConnection->setContentWidgetData("checkState",
            mUnencryptState ? Qt::Checked : Qt::Unchecked);

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_CREATEUNENCRYPTEDBOX_EXIT, this );
    return mUnencryptedConnection;
}

/*!
 Removes provided object from the UI if it exists there and sets the pointer
 to NULL.
 
 @param object object to be removed and nulled.
 */
void CpWpaCmnUiPrivate::removeObjectFromView(CpSettingFormItemData *&object)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_REMOVEOBJECTFROMVIEW_ENTRY, this );

    if (object) {
        mCmnUi->removeChild(mCmnUi->indexOf(object));
        object = NULL;
    }
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_REMOVEOBJECTFROMVIEW_EXIT, this );
}


/*! 
 Load the CpSettingFormItemData components, based on the security 
 mode chosen. Only those components that are required by that security
 mode are loaded
 */
void CpWpaCmnUiPrivate::loadUi()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_LOADUI_ENTRY, this );

    //Read values From CommsDatbase
    int err;
    QT_TRYCATCH_ERROR(err, ( readValues()));
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWPACMNUIPRIVATE_CREATEUI, "CPWPACMNUI ReadValues returned %d", err );
    }

    switch (mSecurityMode)
        {
        case CMManagerShim::WlanSecModeWpa:
        case CMManagerShim::WlanSecModeWpa2:
            createWpaTypeSelector();
            if (mEnablePskMode) {
                loadWPAPskView();
            }
            else {
                loadWPAEapView();
            }
            break;

        case CMManagerShim::WlanSecMode802_1x:
        default:
            Q_ASSERT(mSecurityMode == CMManagerShim::WlanSecMode802_1x);
            createEapSelector();
            createEapEntryItem();
#if 0  /* not supported for now */
            createUnencryptedBox();
#endif /* #if 0 */
            break;
        }

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_LOADUI_EXIT, this );
}

/*! 
 Load the CpSettingFormItemData components,for the
 Pre-Shared key mode
 */
void CpWpaCmnUiPrivate::loadWPAPskView()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_LOADWPAPSKVIEW_ENTRY, this );

    removeObjectFromView(mEapPlugins);

    if (mEapEntry) {
        mCmnUi->removeChild(mCmnUi->indexOf(mEapEntry));
        mEapEntry = NULL;
        }
    createPskEditor();

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_LOADWPAPSKVIEW_EXIT, this );
}

/*! 
 Load the CpSettingFormItemData components,for the
 EAP  mode
 */
void CpWpaCmnUiPrivate::loadWPAEapView()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_LOADWPAEAPVIEW_ENTRY, this );

    removeObjectFromView(mPskKeyText);
    createEapSelector();
    createEapEntryItem();

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_LOADWPAEAPVIEW_EXIT, this );
}

/*!
 * Reads the wlan security wpa/wpa2 related fields from CommsDb 
 */
void CpWpaCmnUiPrivate::loadWPA_WPA2Fields()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_LOADWPA_WPA2FIELDS_ENTRY, this );
    
    mEnablePskMode = mConnMethod->getBoolAttribute(
            CMManagerShim::WlanEnableWpaPsk);
    
    mKeyData = mConnMethod->getString8Attribute(
            CMManagerShim::WlanWpaPreSharedKey);
    
    loadEapConfigurations();
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_LOADWPA_WPA2FIELDS_EXIT, this );
}

/*!
 Reads the WLAN security eap related fields from CommsDb and from EAP Qt 
 Configuration Interface 
 */
void CpWpaCmnUiPrivate::load802Dot1xFields()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_LOAD802DOT1XFIELDS_ENTRY, this );
    
    loadEapConfigurations();
    
    mUnencryptState
            = mConnMethod->getBoolAttribute(CMManagerShim::Wlan802_1xAllowUnencrypted);
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_LOAD802DOT1XFIELDS_EXIT, this );
    }

/*!
 Loads selected EAP method.
 */
void CpWpaCmnUiPrivate::loadEapConfigurations()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_LOADEAPCONFIGURATIONS_ENTRY, this );
    
    QList<EapQtPluginHandle> types = mEapQtConfigInterface->selectedOuterTypes();
    mCurrentEapPlugin = 0;
    if (types.length() > 0) {
        for (int i = 0; i < mPlugins.length(); ++i)
            {
            if (mPlugins.at(i).pluginHandle() == types.at(0)) {
                mCurrentEapPlugin = i;
                break;
            }
        }
   }
 
    else {
        types.append(mPlugins.at(0).pluginHandle());
        mEapQtConfigInterface->setSelectedOuterTypes(types);
    }
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_LOADEAPCONFIGURATIONS_EXIT, this );
}


/*!
 * Reads the wlan security fields from CommsDb 
 */
void CpWpaCmnUiPrivate::readValues()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_READVALUES_ENTRY, this );
    
    switch (mSecurityMode)
        {
        case CMManagerShim::WlanSecModeWpa:
        case CMManagerShim::WlanSecModeWpa2:
            loadWPA_WPA2Fields();
            break;
    
        case CMManagerShim::WlanSecMode802_1x:
        default:
            Q_ASSERT(mSecurityMode == CMManagerShim::WlanSecMode802_1x);
            load802Dot1xFields();
            break;
        }
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_READVALUES_EXIT, this );
}



/*!
 * Tries an Update on Comms Db for the latest settings. 
 * Catches and handles any exception while updating.
 */
bool CpWpaCmnUiPrivate::tryUpdate()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_TRYUPDATE_ENTRY, this );
    int ret(true);
    // Try update
    try {
        mConnMethod->update();
    }
    catch (const std::exception&) {
        // Handle error
        handleUpdateError();
        OstTraceFunctionExit1( CPWPACMNUIPRIVATE_TRYUPDATE_EXIT, this );
        ret = false;
    }
    OstTraceFunctionExit1( DUP1_CPWPACMNUIPRIVATE_TRYUPDATE_EXIT, this );
    return ret;
}

/*!
 Handles failed CommsDat update.
 */
void CpWpaCmnUiPrivate::handleUpdateError()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_HANDLEUPDATEERROR_ENTRY, this );
    // Show error note to user
    showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
            "txt_occ_info_unable_to_save_setting"));
    // Reload settings from CommsDat and update UI
    try {
        mConnMethod->refresh();
    }
    catch (const std::exception&) {
        // Ignore error from refresh. Most likely this will not happen, but
        // if it does, there isn't very much we can do.
        OstTrace0( TRACE_ERROR, CPWPACMNUIPRIVATE_HANDLEUPDATEERROR, "CpWpaCmnUiPrivate::handleUpdateError" );

    };

    //Call reset on Ui elements
    reset();
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_HANDLEUPDATEERROR_EXIT, this );
}

/*!
 Shows message box with "OK" button using given text.
 */
void CpWpaCmnUiPrivate::showMessageBox(HbMessageBox::MessageBoxType type,
    const QString &text)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_SHOWMESSAGEBOX_ENTRY, this );
    // Create a message box
    mMessageBox = QSharedPointer<HbMessageBox> (new HbMessageBox(type));
    mMessageBox->setObjectName("CpWpaCmnUiMessageBox");
    mMessageBox->setText(text);
    mMessageBox->open();
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_SHOWMESSAGEBOX_EXIT, this );
}

/*!
 * Resets all the Ui elements to their previous values,
 * by reading values from DB 
 */
void CpWpaCmnUiPrivate::reset()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_RESET_ENTRY, this );
    
    //Reload Ui with the previous settings (read from Comms )
    loadUi();
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_RESET_EXIT, this );
}

/*!
 Method to handle change in wpa mode :- PSK /EAP, 
 Update Key in Comms

 \param pskEnable the current mode chosen
 */
void CpWpaCmnUiPrivate::updateWpaType(int pskEnable)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_UPDATEWPATYPE_ENTRY, this );
    int err;
    bool PskEnable = pskEnable ? true : false;
    
    QT_TRYCATCH_ERROR(err,mConnMethod->setBoolAttribute(CMManagerShim::WlanEnableWpaPsk, PskEnable));
    
    if (err != KErrNone) {
        OstTrace1( TRACE_ERROR, CPWPACMNUIPRIVATE_UPDATEWPATYPE, "CpWpaCmnUiPrivate::updateWpaType;err=%d", err );
    }
    tryUpdate();
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_UPDATEWPATYPE_EXIT, this );
}

/*!
 Slot to handle change in pre-shared key string

 \param key changed string for PSK
 */
void CpWpaCmnUiPrivate::updatePskKey(QString &key)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_UPDATEPSKKEY_ENTRY, this );
    int err;
    //Check for Validity of Pre-shared Key
    WpaKeyValidator::KeyStatus keystatus = WpaKeyValidator::validateWpaKey(key);
    
    if (keystatus == WpaKeyValidator::KeyStatusOk) {
        QT_TRYCATCH_ERROR(err, mConnMethod->setString8Attribute(CMManagerShim::WlanWpaPreSharedKey, key));
        if (err != KErrNone) {
            OstTrace1( TRACE_ERROR, CPWPACMNUIPRIVATE_UPDATEPSKKEY, "CpWpaCmnUiPrivate::updatePskKey;err=%d", err );
        }
        tryUpdate();
        
        //Store the String that was just set
        mKeyData = key;
    }
    else {
        showMessageBox(HbMessageBox::MessageTypeWarning, hbTrId(
                "txt_occ_info_invalid_input"));
    }
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_UPDATEPSKKEY_EXIT, this );
}



//====================== PRIVATE SLOTS===================================


/*!
 Slot to handle change in wpa mode :- PSK /EAP
 Emits a mode change signal to the  security plugin 
 to indicate the change

 \param pskEnable the current mode chosen
 */
void CpWpaCmnUiPrivate::wpaTypeChanged(int pskEnable)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_WPATYPECHANGED_ENTRY, this );
    
    mEnablePskMode = pskEnable == 0 ? false : true;
    
    if (mEnablePskMode) {
        loadWPAPskView();
    }
    else {
        loadWPAEapView();
    }
    
    //Update pskEnable flag in DB
    updateWpaType(pskEnable);

    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_WPATYPECHANGED_EXIT, this );
}

/*!
 Slot to handle change in eap method in use.
 Emits signal back to the security plugin to indicate 
 the change
 \param currentplugin plugin number to indicate the
 eap method in use
 */
void CpWpaCmnUiPrivate::eapTypeChanged(int eapPlugin)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_EAPTYPECHANGED_ENTRY, this );
    
    mCurrentEapPlugin = eapPlugin;
    QList<EapQtPluginHandle> outerHandles;
    outerHandles.append(mPlugins.at(mCurrentEapPlugin).pluginHandle());
    mEapQtConfigInterface->setSelectedOuterTypes(outerHandles);
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_EAPTYPECHANGED_EXIT, this );
}

/*!
 Slot to handle change in pre-shared key string
 Emits signal back to the security plugin to indicate 
 the change

 */
void CpWpaCmnUiPrivate::pskKeyChanged()
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_PSKKEYCHANGED_ENTRY, this );
    
    QVariant keyValue = mPskKeyText->contentWidgetData("text");
    QString keyString = keyValue.toString();
    
    //Update Pre Shared key in DB
    updatePskKey(keyString);
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_PSKKEYCHANGED_EXIT, this );
}

/*!
 Slot to handle change in the state of unencrypted connection;
 to indicate if such a connection is allowed.
 Emits signal back to the security plugin to indicate 
 the change
 \param state checked-Allowed / Unchecked-Not allowed 
 */
void CpWpaCmnUiPrivate::unencryptConnStateChanged(int state)
{
    OstTraceFunctionEntry1( CPWPACMNUIPRIVATE_UNENCRYPTCONNSTATECHANGED_ENTRY, this );
    
    bool checked  = (state == Qt::Checked) ? true : false;
    mConnMethod->setBoolAttribute(
            CMManagerShim::Wlan802_1xAllowUnencrypted,checked);
    
    tryUpdate();
    
    //store the Unencrypted Connection State
    mUnencryptState  = checked;
    
    OstTraceFunctionExit1( CPWPACMNUIPRIVATE_UNENCRYPTCONNSTATECHANGED_EXIT, this );
}

/*!
 * Slot that configures the editor settings for Pre-Shared Key Field.
 * This slot is invoked whenever a new item(s) are shown in the current view 
 * 
 * \param modelIndex Index of the current item in the  model
 */
void CpWpaCmnUiPrivate::setEditorPreferences(const QModelIndex &modelIndex)
{
    
    HbDataFormModelItem *item = mDataHelper.modelItemFromModelIndex(modelIndex);

    /* Configure settings only for text fields*/
    if(item->type() == HbDataFormModelItem::TextItem) {
        HbLineEdit *edit = qobject_cast<HbLineEdit*>(mDataHelper.widgetFromModelIndex(modelIndex));           
        HbEditorInterface editInterface(edit);    
        editInterface.setInputConstraints(HbEditorConstraintLatinAlphabetOnly);
        edit->setInputMethodHints(Qt::ImhNoPredictiveText);    
        }
}

/*!
   Validates current security settings. This function is called whenever
   user tries to exit from the settings view. If the plugin determines
   that some settings need editing before considered valid, it shall
   return false. A dialog will be shown to the user indicating that
   settings are still incomplete and asking if he/she wishes to exit
   anyway.

   \return True if security settings fpr WPA/WPA2 , WPA2 only are valid,
    false if not.
*/
bool CpWpaCmnUiPrivate::validateSettings()
{
    bool ret(false);
    if(mEnablePskMode) {
        //Check the latest string entered for the Pre-Shared key in the text box
        QVariant keyValue = mPskKeyText->contentWidgetData("text");
        QString keyString = keyValue.toString();
        WpaKeyValidator::KeyStatus keystatus = WpaKeyValidator::validateWpaKey(keyString);
            
            if (keystatus == WpaKeyValidator::KeyStatusOk && (!keyString.isEmpty())) {
            ret= true;
            }
    }
    else{
    //return true if EAP mode
    ret = true;
    }
    return ret;
}

/*!
   comparator for qSort() method to sort Eap plugins based on ordernumber.
   
   @param plugin1 Plugin1
   @param plugin2 Plugin2  
 */
bool CpWpaCmnUiPrivate::pluginLessThan(
    const EapQtPluginInfo &plugin1,
    const EapQtPluginInfo &plugin2)
{
    return plugin1.orderNumber() < plugin2.orderNumber(); 
}


