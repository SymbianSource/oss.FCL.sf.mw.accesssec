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
 *   Control Panel EAP plugin information
 *
 */

/*
 * %version: 15 %
 */

#include "eapqtpluginhandle.h"
#include "eapqtpluginhandle_p.h"

struct EapQtPluginHandleMapper
{
    EapQtExpandedEapType::Type mType;
    int mUid;
};

static const EapQtPluginHandleMapper handleMapper[EapQtPluginHandle::PluginLast] = { 
    {EapQtExpandedEapType::TypeUndefined,     0x00000000},
    {EapQtExpandedEapType::TypeEapAka,        0x102073c2},
    {EapQtExpandedEapType::TypeEapFast,       0x2000BF12},
    {EapQtExpandedEapType::TypeEapGtc,        0x101f8e80},
    {EapQtExpandedEapType::TypeLeap,          0x101f8ea7},
    {EapQtExpandedEapType::TypeEapMschapv2,   0x101f8e67},
    {EapQtExpandedEapType::TypePeap,          0x101f8e4e},
    {EapQtExpandedEapType::TypeEapSim,        0x101f8e4b},
    {EapQtExpandedEapType::TypeEapTls,        0x101f8e4d},
    {EapQtExpandedEapType::TypeEapTtls,       0x101f8e4f},
    {EapQtExpandedEapType::TypePap,           0x2001B2F2},
    {EapQtExpandedEapType::TypePlainMschapv2, 0x101f8e7b}
};

static const EapQtPluginHandle::Plugin typeMapper[EapQtExpandedEapType::TypeLast] = {
    EapQtPluginHandle::PluginUndefined, 
    EapQtPluginHandle::PluginEapAka,
    EapQtPluginHandle::PluginEapFast, 
    EapQtPluginHandle::PluginEapGtc,
    EapQtPluginHandle::PluginLeap, 
    EapQtPluginHandle::PluginEapMschapv2,
    EapQtPluginHandle::PluginPeap, 
    EapQtPluginHandle::PluginEapSim,
    EapQtPluginHandle::PluginEapTls, 
    EapQtPluginHandle::PluginEapTtls,
    EapQtPluginHandle::PluginUndefined, /* no wps plugin */ 
    EapQtPluginHandle::PluginPap,
    EapQtPluginHandle::PluginPlainMschapv2 
};



//----------------------------------------------------------------------------
//              EapQtPluginHandle
//----------------------------------------------------------------------------
EapQtPluginHandle::EapQtPluginHandle() :
    d_ptr(new EapQtPluginHandlePrivate(handleMapper[PluginUndefined].mType,
        handleMapper[PluginUndefined].mUid))
{
}

EapQtPluginHandle::EapQtPluginHandle(Plugin id) :
    d_ptr(NULL)
{
    Plugin localId;
    if (id < PluginLast) {
        localId = id;
    }
    else {
        localId = PluginUndefined;
    }
    d_ptr.reset(new EapQtPluginHandlePrivate(handleMapper[localId].mType,
        handleMapper[localId].mUid));
}

EapQtPluginHandle::EapQtPluginHandle(EapQtExpandedEapType type, int uid) :
    d_ptr(new EapQtPluginHandlePrivate(type, uid))
{
}

EapQtPluginHandle::EapQtPluginHandle(EapQtExpandedEapType type) :
    d_ptr(new EapQtPluginHandlePrivate(type, handleMapper[typeMapper[type.type()]].mUid))
{
}

EapQtPluginHandle::EapQtPluginHandle(const EapQtPluginHandle& handle) :
    d_ptr(new EapQtPluginHandlePrivate(handle.type(), handle.protocolImplementationUid()))
{
}

EapQtPluginHandle::~EapQtPluginHandle()
{
    // scoped pointer delete
}

EapQtExpandedEapType EapQtPluginHandle::type() const
{
    return d_ptr->mType;
}

int EapQtPluginHandle::protocolImplementationUid() const
{
    return d_ptr->mProtocolImplementationUid;
}

EapQtPluginHandle::Plugin EapQtPluginHandle::pluginId() const
{
    return typeMapper[d_ptr->mType.type()];
}

bool EapQtPluginHandle::operator==(const EapQtPluginHandle &other) const
{
    return (other.d_ptr->mProtocolImplementationUid == d_ptr->mProtocolImplementationUid)
        && (other.d_ptr->mType == d_ptr->mType);
}

EapQtPluginHandle& EapQtPluginHandle::operator=(const EapQtPluginHandle &handle)
{
    // check if assigning to myself
    if (this != &handle) {
        d_ptr.reset(new EapQtPluginHandlePrivate(handle.type(), handle.protocolImplementationUid()));
    }
    return *this;
}

