import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox, QCheckBox
from PyQt5.QtCore import Qt
import paramiko
import os

class SSHKeyManagerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('SSH密钥管理器 PowerBy:Sor9ry')

        # 服务器文件信息选择
        self.server_file_label = QLabel('选择服务器信息文件（txt）:')
        self.server_file_edit = QLineEdit()
        self.server_file_button = QPushButton('浏览')
        self.server_file_button.clicked.connect(lambda: self.browse_file('txt'))

        # SSH公钥文件选择
        self.ssh_key_label = QLabel('选择SSH公钥文件:')
        self.ssh_key_edit = QLineEdit()
        self.ssh_key_button = QPushButton('浏览')
        self.ssh_key_button.clicked.connect(lambda: self.browse_file('pub'))

        # 私钥文件选择
        self.private_key_label = QLabel('选择SSH私钥文件:')
        self.private_key_edit = QLineEdit()
        self.private_key_button = QPushButton('浏览')
        self.private_key_button.clicked.connect(lambda: self.browse_file(''))

        # 私钥密码复选框和输入框
        self.private_key_password_checkbox = QCheckBox('使用私钥密码')
        self.private_key_password_checkbox.stateChanged.connect(self.toggle_password_input)
        self.private_key_password_edit = QLineEdit()
        self.private_key_password_edit.setEchoMode(QLineEdit.Password)
        self.private_key_password_edit.setDisabled(True)

        # 使用私钥复选框
        self.use_private_key_checkbox = QCheckBox('使用私钥登录')

        # 操作按钮
        self.generate_key_button = QPushButton('生成密钥')
        self.generate_key_button.clicked.connect(self.generate_ssh_key_pair)
        self.add_button = QPushButton('添加密钥')
        self.add_button.clicked.connect(self.handle_add_ssh_key)
        self.delete_key_button = QPushButton('删除选择的密钥')
        self.delete_key_button.clicked.connect(self.handle_delete_ssh_key)
        self.delete_all_keys_button = QPushButton('删除所有密钥')
        self.delete_all_keys_button.clicked.connect(self.handle_delete_all_ssh_keys)
        self.test_connection_button = QPushButton('测试密钥连接')
        self.test_connection_button.clicked.connect(self.test_ssh_key_connection)
        self.disable_password_login_button = QPushButton('关闭SSH密码登录')
        self.disable_password_login_button.clicked.connect(self.disable_ssh_password_login)
        self.enable_password_login_button = QPushButton('开启SSH密码登录')
        self.enable_password_login_button.clicked.connect(self.enable_ssh_password_login)
        self.clear_output_button = QPushButton('清理输出')
        self.clear_output_button.clicked.connect(self.clear_output)

        # 输出文本
        self.output_text = QTextEdit('Github:https://github.com/sor9rylo\nPowerBy:Sor9ry')
        self.output_text.setReadOnly(True)

        # 布局
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.server_file_label)
        main_layout.addLayout(self.create_hbox_layout(self.server_file_edit, self.server_file_button))
        main_layout.addWidget(self.ssh_key_label)
        main_layout.addLayout(self.create_hbox_layout(self.ssh_key_edit, self.ssh_key_button))
        main_layout.addWidget(self.private_key_label)
        main_layout.addLayout(self.create_hbox_layout(self.private_key_edit, self.private_key_button))
        main_layout.addLayout(self.create_hbox_layout(self.private_key_password_checkbox, self.private_key_password_edit))
        main_layout.addWidget(self.use_private_key_checkbox)
        main_layout.addWidget(self.generate_key_button)
        main_layout.addLayout(self.create_hbox_layout(self.add_button, self.test_connection_button))
        main_layout.addLayout(self.create_hbox_layout(self.delete_key_button, self.delete_all_keys_button))
        main_layout.addLayout(self.create_hbox_layout(self.disable_password_login_button, self.enable_password_login_button))
        main_layout.addWidget(self.clear_output_button)
        main_layout.addWidget(self.output_text)

        self.setLayout(main_layout)

    def create_hbox_layout(self, *widgets):
        layout = QHBoxLayout()
        for widget in widgets:
            layout.addWidget(widget)
        return layout

    def toggle_password_input(self, state):
        self.private_key_password_edit.setDisabled(state != Qt.Checked)

    def browse_file(self, file_type):
        options = QFileDialog.Options()
        file_filter = 'Text files (*.txt)' if file_type == 'txt' else 'SSH Key files (*.pub)' if file_type == 'pub' else 'Private Key files (*)'
        file_path, _ = QFileDialog.getOpenFileName(self, '打开文件', '', file_filter, options=options)
        if file_path:
            if file_type == 'txt':
                self.server_file_edit.setText(file_path)
            elif file_type == 'pub':
                self.ssh_key_edit.setText(file_path)
            else:
                self.private_key_edit.setText(file_path)

    def generate_ssh_key_pair(self):
        private_key_path = 'id_rsa'
        public_key_path = 'id_rsa.pub'

        if os.path.exists(private_key_path) or os.path.exists(public_key_path):
            QMessageBox.information(self, '提示', 'SSH密钥已存在。')
            self.output_text.append('SSH密钥已存在。')
            return

        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(private_key_path)
        with open(public_key_path, 'w') as pub_file:
            pub_file.write(f"{key.get_name()} {key.get_base64()}\n")

        QMessageBox.information(self, '成功', f"SSH密钥已生成:\n私钥: {private_key_path}\n公钥: {public_key_path}")
        self.output_text.append(f"SSH密钥已生成:\n私钥: {private_key_path}\n公钥: {public_key_path}")

    def handle_add_ssh_key(self):
        server_file_path = self.server_file_edit.text()
        ssh_key_path = self.ssh_key_edit.text()
        private_key_path = self.private_key_edit.text()

        if not os.path.isfile(server_file_path) or not os.path.isfile(ssh_key_path):
            QMessageBox.critical(self, '错误', '服务器信息文件或密钥文件未找到。')
            return
        if self.use_private_key_checkbox.isChecked() and not os.path.isfile(private_key_path):
            QMessageBox.critical(self, '错误', 'SSH私钥文件未找到。')
            return

        use_private_key = self.use_private_key_checkbox.isChecked()
        success_count, failure_count = self.process_servers_file(server_file_path, ssh_key_path, private_key_path, use_private_key)

        self.output_text.append(f"\n\n总结:\n成功添加密钥到 {success_count} 台服务器。\n添加密钥失败的服务器数量: {failure_count}。\n\n")

    def handle_delete_ssh_key(self):
        server_file_path = self.server_file_edit.text()
        ssh_key_path = self.ssh_key_edit.text()

        if not os.path.isfile(server_file_path) or not os.path.isfile(ssh_key_path):
            QMessageBox.critical(self, '错误', '服务器信息文件或SSH密钥文件未找到。')
            return

        success_count, failure_count = self.process_servers_file(server_file_path, ssh_key_path, None, False, self.delete_ssh_key_from_server)
        self.output_text.append(f"\n\n总结:\n成功删除密钥从 {success_count} 台服务器。\n删除密钥失败的服务器数量: {failure_count}。\n\n")

    def handle_delete_all_ssh_keys(self):
        server_file_path = self.server_file_edit.text()

        if not os.path.isfile(server_file_path):
            QMessageBox.critical(self, '错误', '服务器信息文件未找到。')
            return

        success_count, failure_count = self.process_servers_file(server_file_path, None, None, False, self.delete_all_ssh_keys_from_server)
        self.output_text.append(f"\n\n总结:\n成功删除所有密钥从 {success_count} 台服务器。\n删除所有密钥失败的服务器数量: {failure_count}。\n\n")

    def process_servers_file(self, file_path, ssh_key_path, private_key_path, use_private_key, action_func=None):
        success_count = 0
        failure_count = 0

        if action_func is None:
            action_func = self.add_ssh_key_to_server_with_key if use_private_key else self.add_ssh_key_to_server

        with open(file_path, 'r') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                parts = line.split(',')
                if len(parts) < 2:
                    continue

                ip_or_domain = parts[0].strip()
                auth_info = parts[1].strip()
                username = parts[2].strip() if len(parts) > 2 else 'root'
                port = int(parts[3].strip()) if len(parts) > 3 else 22

                result = action_func(ip_or_domain, port, username, private_key_path if use_private_key else auth_info, ssh_key_path)

                if result:
                    success_count += 1
                else:
                    failure_count += 1

        return success_count, failure_count

    def add_ssh_key_to_server(self, ip, port, username, password, ssh_key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.output_text.append(f"正在连接 {ip} ，端口 {port} ，用户名 {username}...")
            ssh.connect(ip, port=port, username=username, password=password)
            ssh.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')

            with open(ssh_key_path, 'r') as ssh_key_file:
                ssh_key = ssh_key_file.read().strip()

            command = f'echo "{ssh_key}" >> ~/.ssh/authorized_keys'
            ssh.exec_command(command)

            ssh.close()
            self.output_text.append(f"成功添加密钥到 {ip} ，端口 {port} ，用户名 {username}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

    def add_ssh_key_to_server_with_key(self, ip, port, username, private_key_path, ssh_key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.output_text.append(f"正在连接 {ip} ，端口 {port} ，用户名 {username}...")
            private_key_password = self.private_key_password_edit.text() if self.private_key_password_checkbox.isChecked() else None
            private_key = paramiko.RSAKey.from_private_key_file(private_key_path, password=private_key_password)
            ssh.connect(ip, port=port, username=username, pkey=private_key)
            ssh.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')

            with open(ssh_key_path, 'r') as ssh_key_file:
                ssh_key = ssh_key_file.read().strip()

            command = f'echo "{ssh_key}" >> ~/.ssh/authorized_keys'
            ssh.exec_command(command)

            ssh.close()
            self.output_text.append(f"成功添加密钥到 {ip} ，端口 {port} ，用户名 {username}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

    def delete_ssh_key_from_server(self, ip, port, username, password, ssh_key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.output_text.append(f"正在连接 {ip} ，端口 {port} ，用户名 {username}...")
            ssh.connect(ip, port=port, username=username, password=password)
            ssh.exec_command('mkdir -p ~/.ssh && chmod 700 ~/.ssh')

            with open(ssh_key_path, 'r') as ssh_key_file:
                ssh_key = ssh_key_file.read().strip()

            command = f'grep -v "{ssh_key}" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp && mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys'
            ssh.exec_command(command)

            ssh.close()
            self.output_text.append(f"成功删除密钥从 {ip} ，端口 {port} ，用户名 {username}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

    def delete_all_ssh_keys_from_server(self, ip, port, username, password, _):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.output_text.append(f"正在连接 {ip} ，端口 {port} ，用户名 {username}...")
            ssh.connect(ip, port=port, username=username, password=password)
            ssh.exec_command('rm -f ~/.ssh/authorized_keys')
            ssh.close()
            self.output_text.append(f"成功删除所有密钥从 {ip} ，端口 {port} ，用户名 {username}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

    def test_ssh_key_connection(self):
        server_file_path = self.server_file_edit.text()
        private_key_path = self.private_key_edit.text()

        if not os.path.isfile(server_file_path) or not os.path.isfile(private_key_path):
            QMessageBox.critical(self, '错误', '服务器信息文件或SSH私钥文件未找到。')
            return

        success_count, failure_count = self.process_servers_file(server_file_path, private_key_path, None, True, self.test_ssh_key_connection_to_server)
        self.output_text.append(f"\n\n总结:\n成功测试密钥连接到 {success_count} 台服务器。\n测试密钥连接失败的服务器数量: {failure_count}。\n\n")

    def test_ssh_key_connection_to_server(self, ip, port, username, _, ssh_key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            private_key_password = self.private_key_password_edit.text() if self.private_key_password_checkbox.isChecked() else None
            private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=private_key_password)
            ssh.connect(ip, port=port, username=username, pkey=private_key)
            ssh.close()
            self.output_text.append(f"成功使用密钥连接到 {ip}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

    def clear_output(self):
        self.output_text.clear()

    def disable_ssh_password_login(self):
        server_file_path = self.server_file_edit.text()
        private_key_path = self.private_key_edit.text()

        if not os.path.isfile(server_file_path) or not os.path.isfile(private_key_path):
            QMessageBox.critical(self, '错误', '服务器信息文件或SSH私钥文件未找到。')
            return

        success_count, failure_count = self.process_servers_file(server_file_path, private_key_path, None, True, self.disable_ssh_password_login_on_server)
        self.output_text.append(f"\n\n总结:\n成功关闭SSH密码登录在 {success_count} 台服务器。\n关闭SSH密码登录失败的服务器数量: {failure_count}。\n\n")

    def enable_ssh_password_login(self):
        server_file_path = self.server_file_edit.text()
        private_key_path = self.private_key_edit.text()

        if not os.path.isfile(server_file_path) or not os.path.isfile(private_key_path):
            QMessageBox.critical(self, '错误', '服务器信息文件或SSH私钥文件未找到。')
            return

        success_count, failure_count = self.process_servers_file(server_file_path, private_key_path, None, True, self.enable_ssh_password_login_on_server)
        self.output_text.append(f"\n\n总结:\n成功恢复SSH密码登录在 {success_count} 台服务器。\n恢复SSH密码登录失败的服务器数量: {failure_count}。\n\n")

    def disable_ssh_password_login_on_server(self, ip, port, username, _, ssh_key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.output_text.append(f"正在连接 {ip} ，端口 {port} ，用户名 {username}...")
            private_key_password = self.private_key_password_edit.text() if self.private_key_password_checkbox.isChecked() else None
            private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=private_key_password)
            ssh.connect(ip, port=port, username=username, pkey=private_key)

            ssh.exec_command('sudo sed -i "s/^#*PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config')
            ssh.exec_command('sudo systemctl restart sshd')

            ssh.close()
            self.output_text.append(f"成功关闭SSH密码登录在 {ip} ，端口 {port} ，用户名 {username}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

    def enable_ssh_password_login_on_server(self, ip, port, username, _, ssh_key_path):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.output_text.append(f"正在连接 {ip} ，端口 {port} ，用户名 {username}...")
            private_key_password = self.private_key_password_edit.text() if self.private_key_password_checkbox.isChecked() else None
            private_key = paramiko.RSAKey.from_private_key_file(ssh_key_path, password=private_key_password)
            ssh.connect(ip, port=port, username=username, pkey=private_key)

            ssh.exec_command('sudo sed -i "s/^#*PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config')
            ssh.exec_command('sudo systemctl restart sshd')

            ssh.close()
            self.output_text.append(f"成功恢复SSH密码登录在 {ip} ，端口 {port} ，用户名 {username}")
            return True
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as e:
            self.output_text.append(f"连接 {ip} ，端口 {port} ，用户名 {username} 失败: {e}")
        return False

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ssh_key_manager = SSHKeyManagerApp()
    ssh_key_manager.show()
    sys.exit(app.exec_())
