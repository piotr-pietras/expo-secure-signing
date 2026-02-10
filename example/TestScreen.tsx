import SecureSigning from "expo-secure-signing";
import { useState } from "react";
import { Button, ScrollView, Text, TextInput, View } from "react-native";

export default function TestScreen() {
  const [alias, setAlias] = useState<string>("key-pair-alias");
  const [generated, setGenerated] = useState<string>("");
  const [textToSign, setTextToSign] = useState<string>("text to sign");
  const [removeAlias, setRemoveAlias] = useState<string>("key-pair-alias");
  const [signature, setSignature] = useState<string>("");
  const [verified, setVerified] = useState<boolean>(false);
  const [retrieveAlias, setRetrieveAlias] = useState<string>("key-pair-alias");
  const [retrievedPublicKey, setRetrievedPublicKey] = useState<string>("");

  return (
    <ScrollView style={styles.container}>
      <Group name="Generate Key Pair (should return public key)">
        <TextInput
          style={styles.input}
          placeholder="Enter alias"
          value={alias}
          onChangeText={setAlias}
        />
        <Button
          onPress={() => setGenerated(SecureSigning.generateKeyPair(alias))}
          title="Create Keys"
        />
        <Text style={{ color: generated ? "green" : "red" }}>{generated}</Text>
      </Group>
      <Group name="Aliases list of all key pairs in the keystore">
        {SecureSigning.aliases().map((alias: string) => (
          <Text key={alias}>{alias}</Text>
        ))}
      </Group>
      <Group name="Remove Key Pair">
        <TextInput
          style={styles.input}
          placeholder="Enter alias to remove"
          value={removeAlias}
          onChangeText={setRemoveAlias}
        />
        <Button
          onPress={() => {
            const newLocal = SecureSigning.removeKeyPair(removeAlias);
            console.info(newLocal);
            console.info(SecureSigning.aliases());
          }}
          title="Remove Key Pair"
        />
      </Group>
      <Group name="Get Public Key">
        <TextInput
          style={styles.input}
          placeholder="Enter alias to retrieve public key"
          value={retrieveAlias}
          onChangeText={setRetrieveAlias}
        />
        <Button
          onPress={() =>
            setRetrievedPublicKey(
              SecureSigning.getPublicKey(retrieveAlias, {
                format: 'PEM',
              }) ?? ""
            )
          }
          title="Get Public Key"
        />
        <Text>{retrievedPublicKey}</Text>
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
            console.log(textToSign);
            console.log(alias);
            setSignature(SecureSigning.sign(alias, textToSign));
          }}
          title="Sign"
        />
        <TextInput
          style={styles.input}
          placeholder="Generated signature"
          value={signature}
          onChangeText={setSignature}
        />
        {signature && (
          <>
            <Button
              onPress={() => {
                console.info({});

                try {
                  const verified = SecureSigning.verify(
                    alias,
                    textToSign,
                    signature
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
          </>
        )}
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
};
