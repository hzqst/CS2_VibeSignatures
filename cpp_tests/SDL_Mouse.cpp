#include <SDL3.stub.h>

SDL_Mouse *mouse();

int main() {
    SDL_Mouse *m = mouse();

    (void)m->WarpMouse(nullptr, 0.0f, 0.0f);
    return sizeof(SDL_Mouse) > 0 ? 0 : 1;
}
