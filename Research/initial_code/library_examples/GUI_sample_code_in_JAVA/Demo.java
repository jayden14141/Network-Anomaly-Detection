import javax.swing.*;

public class Demo extends JFrame{
    private JButton button;
    private JLabel label;
    private JComboBox comboBox;
    private JTextArea textArea;
    private JList list;
    private JCheckBox checkBox;
    private JPanel panel;
    private JTextField textField;
    private JRadioButton radioButton1;
    private JRadioButton radioButton2;
    private ButtonGroup buttonGroup;

    public Demo(){
        setTitle("Demo");
        setSize(1080,960);
        setLocationRelativeTo(null);

        textField = new JTextField("Test:");
        //textField.setText("123");

        panel = new JPanel();

        button = new JButton("button");

        label = new JLabel("Test 123");
        textArea = new JTextArea(20,50);

        checkBox = new JCheckBox();

        radioButton1 = new JRadioButton("1");
        radioButton2 = new JRadioButton("2");
        buttonGroup = new ButtonGroup();
        buttonGroup.add(radioButton1);
        buttonGroup.add(radioButton2);
        radioButton1.setSelected(true);

        String[] cities = {"1", "2", "3"};
        list = new JList(cities);
        comboBox = new JComboBox(cities);
        list.setSelectedIndex(2);

        panel.add(textField);
        panel.add(radioButton1);
        panel.add(radioButton2);
        panel.add(button);
        panel.add(label);
        panel.add(comboBox);
        panel.add(textArea);
        panel.add(checkBox);
        panel.add(list);
        add(panel);

        setVisible(true);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);


    }

    public static void main(String[] args) {
        Demo d = new Demo();
    }
}
