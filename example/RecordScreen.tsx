import { useState } from "react";
import {
  Button,
  ScrollView,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { Text } from "react-native";
import SecureSigning, { AuthMethod } from "expo-secure-signing";

export default function RecordScreen() {
  const [authCheckAvailable, setAuthCheckAvailable] = useState<string>("");

  const [alias, setAlias] = useState<string>("key-pair-alias");
  const [generated, setGenerated] = useState<string>("");
  const [textToSign, setTextToSign] = useState<string>("text to sign");
  const [signature, setSignature] = useState<string>("");
  const [retrievedPublicKey, setRetrievedPublicKey] = useState<string>("");

  return (
    <ScrollView style={styles.container}>
      <Group name="Generate Key Pair">
        <TouchableOpacity
          onPress={() => {
            SecureSigning.generateKeyPair("Test", {
              requireAuthentication: true,
            }).then((result) => {
              setGenerated(result);
            });
          }}
        >
          <View style={styles.button}>
            <Text style={styles.buttonText}>Create Keys</Text>
          </View>
        </TouchableOpacity>
        <Text style={{ color: generated ? "green" : "red" }}>{generated}</Text>
      </Group>
      {generated && (
        <Group name="Get Public Key">
          <TouchableOpacity
            onPress={() => {
              setRetrievedPublicKey(
                SecureSigning.getPublicKey("Test", {
                  format: "PEM",
                }) ?? ""
              );
            }}
          >
            <View style={styles.button}>
              <Text style={styles.buttonText}>Get Public Key</Text>
            </View>
          </TouchableOpacity>
          <Text style={{ fontWeight: "bold" }}>{retrievedPublicKey}</Text>
        </Group>
      )}
      {retrievedPublicKey && (
        <Group name="Sign and verify">
          <TextInput
            style={styles.input}
            placeholder="Enter text to sign"
            editable={false}
            selectTextOnFocus={false}
            value={"Test text to sign"}
            onChangeText={setTextToSign}
          />
          <TouchableOpacity
            onPress={() => {
              SecureSigning.sign('Test', textToSign, {
                authMethod: AuthMethod.PASSCODE_OR_BIOMETRIC,
              }).then((result) => {
                setSignature(result ?? "");
              })
            }}
          >
            <View style={styles.button}>
              <Text style={styles.buttonText}>Sign</Text>
            </View>
          </TouchableOpacity>
          <Text style={{ color: signature ? "green" : "red" }}>
            {signature ? "SIGNED_SUCCESSFULLY" : "NOT_SIGNED"}
          </Text>
          <Text style={{ fontWeight: "bold" }}>{signature}</Text>
        </Group>
      )}
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
  button: {
    backgroundColor: "#007AFF",
    padding: 10,
    borderRadius: 5,
    alignItems: "center",
    justifyContent: "center",
  },
  buttonText: {
    color: "#fff",
    fontSize: 16,
  },
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
};
