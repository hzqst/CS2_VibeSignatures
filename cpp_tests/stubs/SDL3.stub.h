// Stub for SDL3.h
// so that igamesystem.h can compile without the full protobuf dependency.
#ifndef SDL3_STUB_H
#define SDL3_STUB_H

#include <stdint.h>

struct SDL_Mouse
{
  void *(*CreateCursor)(void *surface, int hot_x, int hot_y);
  void *(*CreateAnimatedCursor)(void *frames, int frame_count, int hot_x, int hot_y);
  void *(*CreateSystemCursor)(int id);
  bool (*ShowCursor)(void *cursor);
  bool (*MoveCursor)(void *cursor);
  void (*FreeCursor)(void *cursor);
  bool (*WarpMouse)(void *window, float x, float y);
  bool (*WarpMouseGlobal)(float x, float y);
  bool (*SetRelativeMouseMode)(bool enabled);
  bool (*CaptureMouse)(void *window);
  int (*GetGlobalMouseState)(float *x, float *y);
  void *ApplySystemScale;
  void *system_scale_data;
  void *InputTransform;
  void *input_transform_data;
  uint8_t integer_mode_flags;
  float integer_mode_residual_motion_x;
  float integer_mode_residual_motion_y;
  void *focus;
  float x;
  float y;
  float x_accu;
  float y_accu;
  float last_x;
  float last_y;
  float residual_scroll_x;
  float residual_scroll_y;
  double click_motion_x;
  double click_motion_y;
  bool has_position;
  bool relative_mode;
  bool relative_mode_warp_motion;
  bool relative_mode_hide_cursor;
  bool relative_mode_center;
  bool warp_emulation_hint;
  bool warp_emulation_active;
  bool warp_emulation_prohibited;
  uint64_t last_center_warp_time_ns;
  bool enable_normal_speed_scale;
  float normal_speed_scale;
  bool enable_relative_speed_scale;
  float relative_speed_scale;
  bool enable_relative_system_scale;
  uint32_t double_click_time;
  int double_click_radius;
  bool touch_mouse_events;
  bool mouse_touch_events;
  bool pen_mouse_events;
  bool pen_touch_events;
  bool was_touch_mouse_events;
  bool added_mouse_touch_device;
  bool added_pen_touch_device;
  bool auto_capture;
  bool capture_desired;
  void *capture_window;
  int num_sources;
  void *sources;
  void *cursors;
  void *def_cursor;
  void *cur_cursor;
  bool cursor_visible;
  void *internal;
};

#endif // SDL3_STUB_H
