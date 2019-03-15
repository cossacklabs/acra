//
//  AppDelegate.swift
//  AcraWriterSwift
//
//  Created by Anastasiia on 3/5/19.
//  Copyright © 2019 Cossack Labs. All rights reserved.
//

import UIKit
import acrawriter

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?


    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        generateAcraStruct()
        generateAcraStructWithZone()
        
        return true
    }

    
    func generateAcraStruct() {
        print("Generating simple AcraStruct")
        
        // Generate storage keys, AcraWriter is using <client_id>_storage.pub public key
        // https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
        
        let aw = AcraWriter()
        let acraStoragePublicKey = "VUVDMgAAAC19EoDCAjPFi89Z/Y4bLX9FAzVonJ+Z1GmxKJQo/DvJY8K8nw9V"
        let acraStoragePublicKeyData = Data(base64Encoded: acraStoragePublicKey, options: .ignoreUnknownCharacters)!

        do {
            let acraStruct = try aw.createAcraStruct(from: "secret data".data(using: .utf8)!,
                                                     publicKey: acraStoragePublicKeyData,
                                                     zoneID: nil)
            let acraStructBase64 = acraStruct.data.base64EncodedString(options: .lineLength64Characters)
            print("generated acraStruct ->\n\(acraStructBase64)")
            
        } catch let error {
            print("Error occurred while generating AcraStruct \(error)", #function)
            return
        }
    }

    func generateAcraStructWithZone() {
        print("Generating simple AcraStruct with Zone")
        
        // Generate Zone keys, AcraWriter is using <zone_id>_zone.pub public key
        // https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
        
        let aw = AcraWriter()
        
        let zonePublicKey = "VUVDMgAAAC1dStsgAwKbjEzpd3Xptt+hjhFX3Kypbd36qjCF0koFzZHBNPLM"
        let zonePublicKeyData = Data(base64Encoded: zonePublicKey, options: .ignoreUnknownCharacters)!
        let zoneID = "DDDDDDDDNVGIGGzYSCklWQPx"
        let zoneIDData = zoneID.data(using: .utf8)!
        
        do {
            let acraStructWithZone = try aw.createAcraStruct(from: "secret data with zone".data(using: .utf8)!,
                                                             publicKey: zonePublicKeyData,
                                                             zoneID: zoneIDData)
            let acraStructBase64 = acraStructWithZone.data.base64EncodedString(options: .lineLength64Characters)
            print("generated acraStruct with Zone ->\n\(acraStructBase64)")
            
        } catch let error {
            print("Error occurred while generating AcraStruct with Zone \(error)", #function)
            return
        }
    }
}

