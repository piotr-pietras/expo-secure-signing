import { Picker } from "@react-native-picker/picker";
import DeviceCrypto, {
  AuthCheckResult,
  AuthMethod,
  SigningAlgorithm,
  EncryptionAlgorithm,
  FormatType,
} from "expo-device-crypto";
import { useState } from "react";
import {
  Button,
  ScrollView,
  Switch,
  Text,
  TextInput,
  View,
  Clipboard,
  TouchableOpacity,
} from "react-native";

export default function TestScreen() {
  const [authCheckAvailable, setAuthCheckAvailable] = useState<string>("");
  const [strongBoxAvailable, setStrongBoxAvailable] = useState<boolean>(false);
  const [preferStrongBox, setPreferStrongBox] = useState<boolean>(false);
  const [requireAuthentication, setRequireAuthentication] =
    useState<boolean>(false);
  const [removedCount, setRemovedCount] = useState<number>(0);
  const [alias, setAlias] = useState<string>("key-pair-alias");
  const [generated, setGenerated] = useState<string>("");
  const [textToSign, setTextToSign] = useState<string>("text to sign");
  const [signature, setSignature] = useState<string>("");
  const [verified, setVerified] = useState<boolean>(false);
  const [algoType, setAlgoType] = useState<
    SigningAlgorithm | EncryptionAlgorithm
  >(SigningAlgorithm.ECDSA_SECP256R1_SHA256);
  const [format, setFormat] = useState<FormatType>(FormatType.BASE64);
  const [publicKeyFormat, setPublicKeyFormat] = useState<"DER" | "PEM">("DER");
  const [retrievedPublicKey, setRetrievedPublicKey] = useState<string>("");
  const [textToEncrypt, setTextToEncrypt] = useState<string>("text to encrypt");
  const [encrypted, setEncrypted] = useState<string>("");
  const [decrypted, setDecrypted] = useState<string>("");

  return (
    <ScrollView style={styles.container}>
      <Group name="Auth Check Available">
        <Text
          style={{
            color:
              authCheckAvailable === AuthCheckResult.AVAILABLE
                ? "green"
                : "red",
          }}
        >
          {authCheckAvailable}
        </Text>
        <Button
          onPress={() =>
            setAuthCheckAvailable(DeviceCrypto.isAuthCheckAvailable())
          }
          title="Auth Check Available"
        />
        <Text
          style={{
            color: strongBoxAvailable ? "green" : "red",
          }}
        >
          {strongBoxAvailable ? "Available" : "Not Available"}
        </Text>
        <Button
          onPress={() =>
            setStrongBoxAvailable(DeviceCrypto.isStrongBoxAvailable())
          }
          title="Strong Box Available"
        />
      </Group>
      <Group name="Generate Key Pair (should return public key)">
        {DeviceCrypto.aliases().map((alias) => (
          <Text key={alias}>{alias}</Text>
        ))}
        <View style={styles.inline}>
          <Text>Require Authentication</Text>
          <Switch
            value={requireAuthentication}
            onValueChange={setRequireAuthentication}
          />
        </View>
        <View style={styles.inline}>
          <Text>Prefer Strong Box</Text>
          <Switch value={preferStrongBox} onValueChange={setPreferStrongBox} />
        </View>
        <View>
          <Text>Input Format:</Text>
          <Picker
            selectedValue={format}
            onValueChange={(itemValue) =>
              setFormat(itemValue as FormatType)
            }
          >
            <Picker.Item label="Base64" value={FormatType.BASE64} />
            <Picker.Item label="Hex" value={FormatType.HEX} />
          </Picker>
        </View>
        <View>
          <Text>Key Type: </Text>
          <Picker
            selectedValue={algoType}
            onValueChange={(itemValue) =>
              setAlgoType(itemValue as SigningAlgorithm | EncryptionAlgorithm)
            }
          >
            <Picker.Item
              label="ECDSA SECP256R1 SHA256"
              value={SigningAlgorithm.ECDSA_SECP256R1_SHA256}
            />
            <Picker.Item
              label="RSA 2048 OAEP SHA1"
              value={EncryptionAlgorithm.RSA_2048_OAEP_SHA1}
            />
            <Picker.Item
              label="RSA 2048 PKCS1"
              value={EncryptionAlgorithm.RSA_2048_PKCS1}
            />
          </Picker>
        </View>
        <TextInput
          style={styles.input}
          placeholder="Enter alias"
          value={alias}
          onChangeText={setAlias}
        />
        <Button
          onPress={() => {
            DeviceCrypto.removeKeyPair(alias);
            setRemovedCount(removedCount + 1);
          }}
          title="Remove Key Pair"
        />
        <Button
          onPress={() =>
            DeviceCrypto.generateKeyPair(alias, {
              requireAuthentication,
              algorithmType: algoType,
              preferStrongBox,
            })
              .then((result) => {
                setGenerated(result);
              })
              .catch((error) => {
                console.error(error);
              })
          }
          title="Create Keys"
        />
        <Text style={{ color: generated ? "green" : "red" }}>{generated}</Text>

        <View style={styles.inline}>
          <Text>Public Key Format: {publicKeyFormat}</Text>
          <Switch
            value={publicKeyFormat === "PEM"}
            onValueChange={() =>
              setPublicKeyFormat(publicKeyFormat === "PEM" ? "DER" : "PEM")
            }
          />
        </View>
        <Button
          onPress={() =>
            setRetrievedPublicKey(
              DeviceCrypto.getPublicKey(alias, {
                format: publicKeyFormat,
              }) ?? ""
            )
          }
          title="Get Public Key"
        />
        <TouchableOpacity
          onPress={() => {
            Clipboard.setString(retrievedPublicKey);
          }}
        >
          <Text>{retrievedPublicKey}</Text>
        </TouchableOpacity>
      </Group>
      <Group name="Sign and verify">
        <TextInput
          style={styles.input}
          placeholder="Enter text to sign"
          value={textToSign}
          onChangeText={setTextToSign}
        />
        <Button
          onPress={() => {
            DeviceCrypto.sign(alias, textToSign, {
              authMethod: AuthMethod.PASSCODE_OR_BIOMETRIC,
              promptTitle: "TEST",
              promptSubtitle: "TEST",
              signatureFormat: format,
            })
              .then((result) => {
                setSignature(result ?? "");
              })
              .catch((error) => {
                console.error(error);
              });
          }}
          title="Sign"
        />
        <TextInput
          style={[styles.input, { height: 100 }]}
          placeholder="Generated signature"
          multiline={true}
          numberOfLines={4}
          value={signature}
          onChangeText={setSignature}
        />
        <Button
          onPress={async () => {
            try {
              const verified = await DeviceCrypto.verify(
                alias,
                textToSign,
                signature,
                {
                  signatureFormat: format,
                }
              );
              setVerified(verified ?? false);
            } catch (error) {
              console.error(error);
              setVerified(false);
            }
          }}
          title="Verify"
        />
        <Text style={{ color: verified ? "green" : "red" }}>
          {verified ? "Signature verified" : "Signature not verified!"}
        </Text>
      </Group>
      <Group name="Encrypt and decrypt">
        <TextInput
          style={styles.input}
          placeholder="Enter text to encrypt"
          value={textToEncrypt}
          onChangeText={setTextToEncrypt}
        />
        <Button
          onPress={() => {
            DeviceCrypto.encrypt(alias, textToEncrypt, {
              algorithmType: algoType as EncryptionAlgorithm,
              encryptionFormat: format,
            })
              .then((result) => {
                setEncrypted(result ?? "");
              })
              .catch((error) => {
                console.error(error);
              });
          }}
          title="Encrypt"
        />
        <TextInput
          style={[styles.input, { height: 150 }]}
          placeholder="Encrypted text"
          value={encrypted}
          onChangeText={setEncrypted}
          multiline={true}
          numberOfLines={4}
        />
        <Button
          onPress={() => {
            DeviceCrypto.decrypt(alias, encrypted, {
              algorithmType: algoType as EncryptionAlgorithm,
              encryptionFormat: format,
            })
              .then((result) => {
                setDecrypted(result ?? "");
              })
              .catch((error) => {
                console.error(error);
              });
          }}
          title="Decrypt"
        />
        <TouchableOpacity
          onPress={() => {
            Clipboard.setString(decrypted);
          }}
        >
          <Text>{decrypted}</Text>
        </TouchableOpacity>
      </Group>
    </ScrollView>
  );
}

function Group(props: { name: string; children: React.ReactNode }) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupHeader}>{props.name}</Text>
      {props.children}
    </View>
  );
}

const styles = {
  input: {
    borderWidth: 1,
    borderColor: "#ccc",
    borderRadius: 5,
    padding: 10,
  },
  groupHeader: {
    fontSize: 20,
  },
  group: {
    margin: 20,
    backgroundColor: "#fff",
    borderRadius: 10,
    padding: 20,
    gap: 10,
  },
  container: {
    flex: 1,
    backgroundColor: "#eee",
  },
  inline: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
};
