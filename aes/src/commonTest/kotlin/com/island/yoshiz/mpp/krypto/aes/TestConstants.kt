package com.island.yoshiz.mpp.krypto

const val ENCRYPTION_KEY_B64 = "ZyTwtcxfq3db9DSEYtVPwfPz1AcW4l7JBf997UB7qLg="
const val IV_B64 = "vvtoafrxIA5gjdlOv81O7Q=="

const val MESSAGE_LONG = "Don't try to read this text. Top Secret Stuff"
const val MESSAGE_LONG_ENCRYPTED_B64 =
        "moWgSZ6oPuDLQ9laAvLmjhYK2tuzLqEFVGlkeZ6Md1C3/N9KPPbNNuzAGk2W9PD9"

const val MESSAGE_BELOW_BLOCK_SIZE = "Just Don't"
const val MESSAGE_BELOW_BLOCK_SIZE_ENCRYPTED_B64 = "9m232g31HbfohFMlPcx62A=="

const val MESSAGE_REALLY_LONG =
        "Don't try to read this text. Top Secret Stuff that needs to be long" +
                " enough so that the encrypted result is more than 2 blocs long."
const val MESSAGE_REALLY_LONG_ENCRYPTED_B64 =
        "moWgSZ6oPuDLQ9laAvLmjhYK2tuzLqEFVGlkeZ6Md1APhXoy22YH" +
                "JyiwSOqM1S3iE2GfDADW079SIgP4/mzuzBzB6EmOU5exSpy0Rb6sPoiSVCMIilYx2+OfnrsZS4j3AFJVTyx1zXyqQLd" +
                "Mn+YsyhNdD8wkres7jwM0p3hQk6oOAm6rDyRRJFNsP5Mo4yvJ"
