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
 *    Control Panel QT UI for WPA/WPA2/802_Dot_1x configuration
 *
 */

/*
 * %version: 17 %
 */

// System includes
#include <QStringList>
#include <eapqtconfiginterface.h>
#include <cmconnectionmethod_shim.h>
#include <cmmanagerdefines_shim.h>

// User includes
#include "cpwpacmnui.h"
//#include "cpwpacmneapui.h"

#include "OstTraceDefinitions.h"
#ifdef OST_TRACE_COMPILER_IN_USE
#include "cpwpacmnuiTraces.h"
#endif

/*!
 \class CpWpaCmnUi
 \brief CpWpaCmnUi implements the common Ui for WPA/WPA2/802.1x/WPA2 only 
 Security Settings Control Panel Plugins,
 which will allow viewing/editing of WPA/WPA2/802.1x/WPA2 Security Settings.
 */
//Contructs Common Ui (WPA/WPA2/802.1x/WPA2only) object
CpWpaCmnUi::CpWpaCmnUi(CMManagerShim::WlanSecMode securityMode, CpItemDataHelper &dataHelpper) :
    mCmnUi(NULL), mDataHelper(dataHelpper), mPskKeyText(NULL), mEapPlugins(
            NULL), mWpaEapItem(NULL), mEapEntry(NULL)
{
    mSecurityMode = securityMode;
    mEnablePskMode = true;
}
//Deletes objects owned by Common Ui
CpWpaCmnUi::~CpWpaCmnUi()
{
    //delete all dynamically allocated objects
    OstTraceFunctionEntry1(CPWPACMNUI_CPWPACMNUI_ENTRY,this);

    mCmnUi = NULL;
    
    mConnMethod = NULL;

    OstTraceFunctionExit1(CPWPACMNUI_CPWPACMNUI_EXIT,this);
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

CpSettingFormItemData* CpWpaCmnUi::createUi(
        EapQtConfigInterface *eapQtConfigInterface,
        CmConnectionMethodShim *cmCM)
{

    OstTraceFunctionEntry1(CPWPACMNUI_CREATEUI_ENTRY,this);
    int err;

    mConnMethod = cmCM;

    //Read values From CommsDatbase
    QT_TRYCATCH_ERROR(err, ( readValues()));
    if(err !=KErrNone) {
          OstTrace1( TRACE_ERROR, CPWPACMNUI_CREATEUI, "CPWPACMNUI ReadValues returned %d", err );
    }

    mCmnUi = new CpSettingFormItemData(HbDataFormModelItem::GroupItem,
            hbTrId("txt_occ_subhead_security_settings"));

    mEapQtConfigInterface = eapQtConfigInterface;
    //mPlugins.append(mEapQtConfigInterface->supportedOuterTypes());

    //PSK / EAP ?
    mWpaEapItem = new CpSettingFormItemData(
            HbDataFormModelItem::ComboBoxItem, hbTrId(
                    "txt_occ_setlabel_wpawpa2"),mCmnUi);
    QStringList wpatype;
    //wpatype.append(hbTrId("txt_occ_setlabel_wpawpa2_val_eap"));
    wpatype.append(hbTrId("txt_occ_setlabel_wpawpa2_val_preshared_key"));

    mWpaEapItem->setContentWidgetData("items", wpatype);
    mWpaEapItem->setContentWidgetData("currentIndex",0/*To use mEnablePskMode when both modes are available*/);

    mDataHelper.addConnection(mWpaEapItem,
            SIGNAL(currentIndexChanged(int)), this,
            SLOT(wpaTypeChanged(int)));

    //1.Pre-Shared Key
    mPskKeyText = new CpSettingFormItemData(
            HbDataFormModelItem::TextItem, hbTrId(
                    "txt_occ_setlabel_preshared_key"),mCmnUi);

    mPskKeyText->setContentWidgetData("text", mKeyData);
    mPskKeyText->setContentWidgetData("echoMode", 2);

    mPskKeyText->setContentWidgetData("smileysEnabled", "false");
    mDataHelper.addConnection(mPskKeyText, SIGNAL( editingFinished ()),
            this, SLOT(pskKeyChanged() ));

    //2.EAP
    /*  mEapPlugins = new CpSettingFormItemData(
                HbDataFormModelItem::ComboBoxItem, hbTrId(
                        "txt_occ_setlabel_eap_type"));

        QStringList items;
        for (int i = 0; i < mPlugins.length(); ++i)
            {
            items << mPlugins.at(i)->localizationId();
            }
        mPluginCurrent = 0;
        mEapPlugins->setContentWidgetData("items", items);
        //Set the last EAP chosen , by reading from CommsDb
        mDataHelper.addConnection(mEapPlugins,
                SIGNAL(currentIndexChanged(int)), this,
                SLOT(eapTypeChanged(int)));

        mEapEntry = new EapEntyItemData(this, mDataHelper, hbTrId(
                "txt_occ_button_eap_type_settings"), QString(""));*/

    mUnencryptedConnection = new CpSettingFormItemData(
            HbDataFormModelItem::CheckBoxItem, hbTrId(
                    "txt_occ_setlabel_unencrypted_connection"),mCmnUi);

    mUnencryptedConnection->setContentWidgetData("text", hbTrId(
            "txt_occ_setlabel_unencrypted_connection_val_allowe"));

    //Kept Unchecked by default , but to be read from Comms DB
    mUnencryptedConnection->setContentWidgetData("checkState",
            "Unchecked");

    mDataHelper.addConnection(mUnencryptedConnection,
            SIGNAL( stateChanged(int)), this,
            SLOT(unencryptConnStateChanged(int)));

    //LoadUi based on the security mode 
    loadUi();

    OstTraceFunctionExit1(CPWPACMNUI_CREATEUI_EXIT,this);
    return mCmnUi;

}

// ======== LOCAL FUNCTIONS ========

/*! 
 Load the CpSettingFormItemData components, based on the security 
 mode chosen. Only those components that are required by that security
 mode are loaded
 */
void CpWpaCmnUi::loadUi()
{
    OstTraceFunctionEntry1(CPWPACMNUI_LOADUI_ENTRY,this);
    int secMode = mSecurityMode;
    switch (secMode)
        {
        case CMManagerShim::WlanSecModeWpa:
        case CMManagerShim::WlanSecModeWpa2:
            {
                if (mEnablePskMode) {
                    mCmnUi->appendChild(mWpaEapItem);
                    mCmnUi->appendChild(mPskKeyText);
                }
                /*else {
                    //do nothing, no EAP 
                    mCmnUi->appendChild(mWpaEapItem);
                    mCmnUi->appendChild(mEapPlugins);
                    mCmnUi->appendChild(mEapEntry);
                }*/

            }
            break;

        /*case CMManagerShim::WlanSecMode802_1x:
            {
            mCmnUi->appendChild(mEapPlugins);
            mCmnUi->appendChild(mEapEntry);
            mCmnUi->appendChild(mUnencryptedConnection);
            }
            break;*/
        default:
            break;
        } 
    OstTraceFunctionExit1(CPWPACMNUI_LOADUI_EXIT,this);
}

/*! 
 Load the CpSettingFormItemData components,for the
 Pre-Shared key mode
 */
/*void CpWpaCmnUi::loadWPAPskView()
{
    OstTraceFunctionEntry1(CPWPACMNUI_LOADWPAPSKVIEW_ENTRY,this);
    mCmnUi->appendChild(mPskKeyText);
    OstTraceFunctionExit1(CPWPACMNUI_LOADWPAPSKVIEW_EXIT,this);
}*/

/*! 
 Load the CpSettingFormItemData components,for the
 EAP  mode
 */
/*void CpWpaCmnUi::loadWPAEapView()
{
    OstTraceFunctionEntry1(CPWPACMNUI_LOADWPAEAPVIEW_ENTRY,this);
    mCmnUi->appendChild(mEapPlugins);
    mCmnUi->appendChild(mEapEntry);
    OstTraceFunctionExit1(CPWPACMNUI_LOADWPAEAPVIEW_EXIT,this);
}*/

/*! 
 Load the CpSettingFormItemData components,for the
 EAP  mode
 */
/*CpBaseSettingView* CpWpaCmnUi::eapUiInstance()
{
    OstTraceFunctionEntry1(CPWPACMNUI_EAPUIINSTANCE_ENTRY,this); 
    OstTraceFunctionExit1(CPWPACMNUI_EAPUIINSTANCE_EXIT,this);

    return mEapQtConfigInterface->uiInstance(
            mPlugins.at(mPluginCurrent)->pluginHandle());
    return NULL;
}*/

/*!
 Slot to handle change in wpa mode :- PSK /EAP
 Emits a mode change signal to the  security plugin 
 to indicate the change

 \param pskEnable the current mode chosen
 */
/*void CpWpaCmnUi::wpaTypeChanged(int pskEnable)
{
    OstTraceFunctionEntry1(CPWPACMNUI_WPATYPECHANGED_ENTRY,this);
    switch (pskEnable)
        {
        case 0:
            {
            RemovePskView();
            LoadWPAEapView();
            }
            break;

        case 1:
            {
            RemoveEapView();
            LoadWPAPskView();
            }
            break;
        } //do nothing , only PSK mode, no EAP
    OstTraceFunctionExit1(CPWPACMNUI_WPATYPECHANGED_EXIT,this);
    //Emit signal back to plugin
    emit pskEapModeToggled(pskEnable);
}*/

/*!
 * Unload components related to Pre-Shared key mode
 */
/*void CpWpaCmnUi::removePskView()
{
    OstTraceFunctionEntry1(CPWPACMNUI_REMOVEPSKVIEW_ENTRY,this);
    int indexOfPsk = mCmnUi->indexOf(mPskKeyText);
    mCmnUi->removeChild(indexOfPsk);
    OstTraceFunctionExit1(CPWPACMNUI_REMOVEPSKVIEW_EXIT,this);
}*/

/*!
 * Unload components related to EAP mode
 */
/*void CpWpaCmnUi::removeEapView()
{
    OstTraceFunctionEntry1(CPWPACMNUI_REMOVEEAPVIEW_ENTRY,this);
    int indexOfEapPlugin = mCmnUi->indexOf(mEapPlugins);
    mCmnUi->removeChild(indexOfEapPlugin);

    int indexOfEapEntry = mCmnUi->indexOf(mEapEntry);
    mCmnUi->removeChild(indexOfEapEntry);
    OstTraceFunctionExit1(CPWPACMNUI_REMOVEEAPVIEW_EXIT,this);
}*/

/*!
 Slot to handle change in eap method in use.
 Emits signal back to the security plugin to indicate 
 the change
 \param currentplugin plugin number to indicate the
 eap method in use
 */
/*void CpWpaCmnUi::eapTypeChanged(int eapPlugin)
{
    OstTraceFunctionEntry1(CPWPACMNUI_EAPTYPECHANGED_ENTRY,this);
    mPluginCurrent = eapPlugin;
    OstTraceFunctionExit1(CPWPACMNUI_EAPTYPECHANGED_EXIT,this);
    emit eapPluginChanged(mPluginCurrent);
}*/

/*!
 Slot to handle change in pre-shared key string
 Emits signal back to the security plugin to indicate 
 the change

 */
void CpWpaCmnUi::pskKeyChanged()
{
    OstTraceFunctionEntry1(CPWPACMNUI_PSKKEYCHANGED_ENTRY,this);
    QVariant keyValue = mPskKeyText->contentWidgetData("text");
    QString keyString = keyValue.toString();
    OstTraceFunctionExit1(CPWPACMNUI_PSKKEYCHANGED_EXIT,this);
    //Emit signal back to plugin
    emit keyChanged(keyString);
}

/*!
 Slot to handle change in the state of unencrypted connection;
 to indicate if such a connection is allowed.
 Emits signal back to the security plugin to indicate 
 the change
 \param state checked-Allowed / Unchecked-Not allowed 
 */
/*void CpWpaCmnUi::unencryptConnStateChanged(int state)
{
    OstTraceFunctionEntry1(CPWPACMNUI_UNENCRYPTCONNSTATECHANGED_ENTRY,this); emit
    connectionStateChanged(state);
    OstTraceFunctionExit1(CPWPACMNUI_UNENCRYPTCONNSTATECHANGED_EXIT,this);
}*/

/*!
 * Reads the wlan security fields from CommsDb 
 */
void CpWpaCmnUi::readValues()
{
    OstTraceFunctionEntry1(CPWPACMNUI_READVALUES_ENTRY,this);
    switch (mSecurityMode)
        {
        case CMManagerShim::WlanSecModeWpa:
        case CMManagerShim::WlanSecModeWpa2:
            {
            loadWPA_WPA2Fields();
            }
            break;

       /* case CMManagerShim::WlanSecMode802_1x:
            {
            load802Dot1xFields();
            }
            break;*/

        default:
            break;
        } 
    OstTraceFunctionExit1(CPWPACMNUI_READVALUES_EXIT,this);
}

/*!
 * Reads the wlan security wpa/wpa2 related fields from CommsDb 
 */
void CpWpaCmnUi::loadWPA_WPA2Fields()
{
    OstTraceFunctionEntry1(CPWPACMNUI_LOADWPAFIELDS_ENTRY,this);
    /*mEnablePskMode = mConnMethod->getIntAttribute(
            CMManagerShim::WlanEnableWpaPsk);*/
			
	 //only PSK mode enabled(temporary);to be read from Comms later
    mEnablePskMode = true ; 		
    
    //set the same to Comms(temporary) ; the mode to be set , depends on what user chooses 
    //between PSK & EAP
     mConnMethod->setBoolAttribute(CMManagerShim::WlanEnableWpaPsk,mEnablePskMode);
			
    if (mEnablePskMode) {
        mKeyData = mConnMethod->getString8Attribute(
                CMManagerShim::WlanWpaPreSharedKey);
    }
   /* else {
        //mcurrentEapPlugin = mCMExtShim->GetIntAttribute( use appropriate enum to get the eap plugin index );
    } */
    OstTraceFunctionExit1(CPWPACMNUI_LOADWPAFIELDS_EXIT,this);
}

/*!
 * Reads the wlan security eap related fields from CommsDb 
 */
/*void CpWpaCmnUi::load802Dot1xFields()
{
    OstTraceFunctionEntry1(CPWPACMNUI_LOAD802DOT1XFIELDS_ENTRY,this);
    //mcurrentEapPlugin = mCMExtShim->GetIntAttribute(use appropriate enum to get the eap plugin index);

    //unencryptStateChanged = mConnMethod->getIntAttribute(CMManagerShim::EWlan802_1xAllowUnencrypted);
    OstTraceFunctionExit1(CPWPACMNUI_LOAD802DOT1XFIELDS_EXIT,this);
}*/

/*!
 * Reset the values on the corresponding Ui elements
 */
void CpWpaCmnUi::reset()
    {
    OstTraceFunctionEntry1(CPWPACMNUI_RESET_ENTRY,this);
    //Read values from Comms and update the Ui items
    readValues();
    
    switch (mSecurityMode)
          {
          case CMManagerShim::WlanSecModeWpa:
          case CMManagerShim::WlanSecModeWpa2:
              {
                  if(mEnablePskMode) {
                      mPskKeyText->setContentWidgetData("text", mKeyData);
                  }
              }
              break;

          /*case CMManagerShim::WlanSecMode802_1x:
              {
              //Set appropriate value in widget for 802.1x
              if(mEnablePskMode) {
              mPskKeyText->setContentWidgetData("checkState", mKeyData);
              }
              break;*/

          default:
              break;
          }
    OstTraceFunctionExit1(CPWPACMNUI_RESET_EXIT,this);
    }

