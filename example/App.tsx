import { Button, KeyboardAvoidingView } from "react-native";
import TestScreen from "./TestScreen";
import { useState } from "react";
import RecordScreen from "./RecordScreen";

export default function App() {
  const [recordScreen, setRecordScreen] = useState(false);

  return (
    <KeyboardAvoidingView style={styles.container} behavior="padding">
      {recordScreen ? <RecordScreen /> : <TestScreen />}
      {!recordScreen && (
        <Button
          title="switch to record screen"
          onPress={() => setRecordScreen(true)}
        />
      )}
    </KeyboardAvoidingView>
  );
}

const styles = {
  container: {
    marginTop: 64,
    flex: 1,
    backgroundColor: "#eee",
  },
};
