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
 * %version: 2 %
 */

#ifndef CPWEPPLUGIN_H
#define CPWEPPLUGIN_H

// System includes
#include <cpsettingformitemdata.h>
#include <QStringList>
#include <HbMessageBox>
#include <cpwlansecurityplugininterface.h>

// User Includes

// Forward declarations
class CmConnectionMethodShim;
class HbTranslator;
class WepKeyValidator;

// External data types

// Constants

/*! 
 * Implements WEP plugin for Wlan security control panel  
 */

// Class declaration
class CpWepPlugin : public QObject, public CpWlanSecurityPluginInterface
{
    Q_OBJECT
    Q_INTERFACES(CpWlanSecurityPluginInterface)

public: // CpWepPlugin public methods
    
    CpWepPlugin();
    
    ~CpWepPlugin();

public: // from CpWlanSecurityPluginInterface 

    CMManagerShim::WlanSecMode securityMode() const;

    QString securityModeTextId() const;
    
    void setReference(CmConnectionMethodShim *cmCm, uint id);
    
    int orderNumber() const;
    
    CpSettingFormItemData* uiInstance(CpItemDataHelper &dataHelper);

signals:

public slots:

protected:

protected slots:

private: // Private methods

private slots:

private: // Private data

    Q_DISABLE_COPY(CpWepPlugin)
   
    //!Translator for all the localisation Text Id's
    QScopedPointer<HbTranslator> mTranslator;

    //!Connection Settings Shim connection method pointer
    CmConnectionMethodShim *mCmCM;

    //! Connection method Id
    int mCmId;        

};

/*! @} */

#endif /* CPWEPPLUGIN_H */
