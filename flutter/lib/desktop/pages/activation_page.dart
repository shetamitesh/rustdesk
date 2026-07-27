import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/desktop/widgets/tabbar_widget.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:get/get.dart';
import 'package:window_manager/window_manager.dart';

/// Reactive activation flag. `main.dart` swaps between the activation screen and
/// the normal app based on this, so a successful activation takes effect without
/// restarting the process.
final RxBool rxActivated = false.obs;

/// Uppercases input so keys can be typed in any case.
class UpperCaseTextFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(
      TextEditingValue oldValue, TextEditingValue newValue) {
    return TextEditingValue(
      text: newValue.text.toUpperCase(),
      selection: newValue.selection,
    );
  }
}

class ActivationPage extends StatefulWidget {
  const ActivationPage({Key? key}) : super(key: key);

  @override
  State<ActivationPage> createState() => _ActivationPageState();
}

class _ActivationPageState extends State<ActivationPage> {
  final tabController = DesktopTabController(tabType: DesktopTabType.main);

  _ActivationPageState() {
    Get.put<DesktopTabController>(tabController);
    const label = "activation";
    tabController.add(TabInfo(
      key: label,
      label: label,
      closable: false,
      page: const _ActivationBody(key: ValueKey(label)),
    ));
  }

  @override
  void dispose() {
    super.dispose();
    Get.delete<DesktopTabController>();
  }

  @override
  Widget build(BuildContext context) {
    return DragToResizeArea(
      resizeEdgeSize: stateGlobal.resizeEdgeSize.value,
      enableResizeEdges: windowManagerEnableResizeEdges,
      child: Container(
        child: Scaffold(
          backgroundColor: Theme.of(context).colorScheme.background,
          body: DesktopTab(controller: tabController),
        ),
      ),
    );
  }
}

class _ActivationBody extends StatefulWidget {
  const _ActivationBody({Key? key}) : super(key: key);

  @override
  State<_ActivationBody> createState() => _ActivationBodyState();
}

class _ActivationBodyState extends State<_ActivationBody> {
  final _controller = TextEditingController();
  bool _loading = false;
  String _error = '';
  late final String _machineId;

  @override
  void initState() {
    super.initState();
    _machineId = bind.mainGetMachineFingerprint();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _activate() async {
    final key = _controller.text.trim();
    if (key.isEmpty) {
      setState(() => _error = 'Please enter an activation key');
      return;
    }
    setState(() {
      _loading = true;
      _error = '';
    });
    // Runs on a background thread (async FFI) so the UI stays responsive.
    final err = await bind.mainActivate(key: key);
    if (!mounted) return;
    if (err.isEmpty) {
      // Activated — start the service that was withheld and reveal the app.
      try {
        gFFI.serverModel.startService();
      } catch (_) {}
      rxActivated.value = true;
    } else {
      setState(() {
        _loading = false;
        _error = err;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: SingleChildScrollView(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 460),
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.vpn_key_rounded, size: 56, color: theme.colorScheme.primary),
                const SizedBox(height: 20),
                Text(
                  'Activate ${bind.mainGetAppNameSync()}',
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                Text(
                  'This copy needs to be activated before it can be used. '
                  'Enter the activation key provided to you.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 13, color: theme.hintColor),
                ),
                const SizedBox(height: 28),
                TextField(
                  controller: _controller,
                  autofocus: true,
                  enabled: !_loading,
                  textCapitalization: TextCapitalization.characters,
                  inputFormatters: [UpperCaseTextFormatter()],
                  onSubmitted: (_) => _loading ? null : _activate(),
                  decoration: InputDecoration(
                    labelText: 'Activation key',
                    hintText: 'XXXXX-XXXXX-XXXXX-XXXXX',
                    border: const OutlineInputBorder(),
                    errorText: _error.isEmpty ? null : _error,
                  ),
                ),
                const SizedBox(height: 20),
                SizedBox(
                  height: 44,
                  child: ElevatedButton(
                    onPressed: _loading ? null : _activate,
                    child: _loading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Text('Activate'),
                  ),
                ),
                const SizedBox(height: 24),
                // Machine ID — read it out to support if a key won't bind (e.g. a
                // hardware change) so they can free the key server-side.
                _machineIdRow(theme),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: () async {
                    await windowManager.close();
                  },
                  child: Text('Exit', style: TextStyle(color: theme.hintColor)),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _machineIdRow(ThemeData theme) {
    final shortId = _machineId.length > 16 ? _machineId.substring(0, 16) : _machineId;
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Text('Machine ID: ', style: TextStyle(fontSize: 12, color: theme.hintColor)),
        SelectableText(
          shortId,
          style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
        ),
        IconButton(
          icon: const Icon(Icons.copy, size: 14),
          tooltip: 'Copy full Machine ID',
          onPressed: () {
            Clipboard.setData(ClipboardData(text: _machineId));
            showToast('Copied');
          },
        ),
      ],
    );
  }
}
