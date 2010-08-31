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
 *   Expanded EAP type QT data structure
 *
 */

/*
 * %version: 6 %
 */

// System includes
#include <EapExpandedType.h>

// User includes
#include "eapqtexpandedeaptype_p.h"

/*!
 *  \class EapQtExpandedEapTypePrivate
 *  \brief Private implementation of expanded EAP type QT data structure
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtExpandedEapTypePrivate::EapQtExpandedEapTypePrivate()
{
    mData.clear();
    mType = EapQtExpandedEapType::TypeUndefined;
}

EapQtExpandedEapTypePrivate::EapQtExpandedEapTypePrivate(const EapQtExpandedEapType::Type type)
{
    TBuf8<KEapExpandedTypeLength> tmpType;
    TEapExpandedType tmpEapType;

    mType = type;
    mData.clear();

    // little bit playing with the types and constructors below to convert to QByteArray

    switch (type) {
    case EapQtExpandedEapType::TypeEapAka:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeAka.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeEapFast:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeFast.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeEapGtc:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeGtc.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeLeap:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeLeap.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeEapMschapv2:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeMsChapv2.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypePeap:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypePeap.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeEapSim:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeSim.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeEapTls:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeTls.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeEapTtls:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeTtls.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeProtectedSetup:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeProtectedSetup.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypePap:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeTtlsPap.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypePlainMschapv2:
    {
        TEapExpandedType localTmpEapType(*EapExpandedPlainMsChapv2.GetType());
        tmpEapType = localTmpEapType;
    }
        break;
    case EapQtExpandedEapType::TypeUndefined:
    default:
    {
        TEapExpandedType localTmpEapType(*EapExpandedTypeNone.GetType());
        tmpEapType = localTmpEapType;
        mType = EapQtExpandedEapType::TypeUndefined;
    }
        break;
    }

    tmpType = tmpEapType.GetValue();
    mData.append(reinterpret_cast<const char*> (tmpType.Ptr()), tmpType.Length());
}

EapQtExpandedEapTypePrivate::EapQtExpandedEapTypePrivate(const QByteArray &data)
{
    mData = data;

    TEapExpandedType tmpType;
    tmpType.SetValue(data.data(), data.size());

    if (tmpType.GetValue() == *(EapExpandedTypeGtc.GetType())) {
        mType = EapQtExpandedEapType::TypeEapGtc;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeTls.GetType())) {
        mType = EapQtExpandedEapType::TypeEapTls;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeLeap.GetType())) {
        mType = EapQtExpandedEapType::TypeLeap;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeSim.GetType())) {
        mType = EapQtExpandedEapType::TypeEapSim;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeAka.GetType())) {
        mType = EapQtExpandedEapType::TypeEapAka;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeTtls.GetType())) {
        mType = EapQtExpandedEapType::TypeEapTtls;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypePeap.GetType())) {
        mType = EapQtExpandedEapType::TypePeap;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeMsChapv2.GetType())) {
        mType = EapQtExpandedEapType::TypeEapMschapv2;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeFast.GetType())) {
        mType = EapQtExpandedEapType::TypeEapFast;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeProtectedSetup.GetType())) {
        mType = EapQtExpandedEapType::TypeProtectedSetup;

    }
    else if (tmpType.GetValue() == *(EapExpandedTypeTtlsPap.GetType())) {
        mType = EapQtExpandedEapType::TypePap;

    }
    else if (tmpType.GetValue() == *(EapExpandedPlainMsChapv2.GetType())) {
        mType = EapQtExpandedEapType::TypePlainMschapv2;
    }
    else {
        mType = EapQtExpandedEapType::TypeUndefined;
        mData = QByteArray(reinterpret_cast<const char*> ((*EapExpandedTypeNone.GetType()).Ptr()),
            (*EapExpandedTypeNone.GetType()).Length());
    }
    qDebug("EapQtExpandedEapTypePrivate(const QByteArray data) - mType: %d", mType);
}

EapQtExpandedEapTypePrivate::~EapQtExpandedEapTypePrivate()
{
}
