# Home Radar film: Mac render handoff

You are Claude Code running on Max Doubin's Mac. Max is finishing a 2.5-minute demo video for the Congressional App Challenge (deadline 6 PM Pacific today). A cloud machine is rendering animated 3D shots in software and is too slow, so your job is to render some of them here on the Mac's real GPU, then push the finished clips back. Do exactly this and nothing else. Do not change the scene code unless a render fails.

## What this kit is

- `film/3d/` three.js scenes of a laptop, monitor and phone showing the real app screenshots. `render3d2.js` renders one shot to two MP4s.
- `film/bg/` slow animated backgrounds for the text-only scenes. `render.js` renders one to two MP4s.
- `film/media/` the nine app screenshots the 3D scenes use as textures.

Outputs land in `film/media/` as `shot-<name>.mp4` (1920x1080, 60 fps) and `shot-<name>-4k.mp4` (3840x2160, 60 fps), or `<bgname>.mp4` and `<bgname>-4k.mp4`.

## 1. Setup (about 5 minutes)

Check `node -v` (needs 18 or newer) and `ffmpeg -version` (install with `brew install ffmpeg` if missing). Then:

```bash
cd film/3d && npm install three@0.169.0 playwright && npx playwright install chromium && cd ..
ln -sfn ../3d/node_modules bg/node_modules
```

`render.js` in `bg/` loads Playwright from `film/3d/node_modules`, so keep the symlink above (or run `npm install playwright` inside `bg/` too).

The renderers use software rendering by default. On the Mac, set `GPU=1` so Chromium uses Metal. That is the whole point of this handoff.

## 2. Test one frame first

```bash
cd film/3d
GPU=1 node render3d2.js --shot overview --dur 6.11 --stills 3 --stilldir /tmp/hr-test --port 8300
```

Open the PNG in `/tmp/hr-test`. It should be a 3840x2160 picture of a monitor showing the Home Radar dashboard on a black floor with a soft reflection. If the page is blank or black, retry once without `GPU=1`; if that works, tell Max the GPU path failed and continue in software mode.

## 3. Render these shots, in this order

Run them one at a time (never in parallel). From `film/3d`:

| Shot | Duration (s) |
|---|---|
| report-card | 8.35 |
| privacy | 6.25 |
| bedtime | 5.58 |
| habits | 7.32 |

```bash
for s in "report-card 8.35" "privacy 6.25" "bedtime 5.58" "habits 7.32"; do set -- $s
  GPU=1 node render3d2.js --shot $1 --dur $2 --port 8300 > /tmp/hr-$1.log 2>&1 && echo "$1 done"
done
```

Then from `film/bg`, the backgrounds:

| Name | Shot | Duration (s) |
|---|---|---|
| bg-close | close | 6.3 |
| bg-price | price | 6.6 |
| bg-question | question | 7.2 |

```bash
cd ../bg
for s in "close 6.3 bg-close" "price 6.6 bg-price" "question 7.2 bg-question"; do set -- $s
  GPU=1 node render.js --shot $1 --dur $2 --name $3 --port 8133 > /tmp/hr-$3.log 2>&1 && echo "$3 done"
done
```

If a shot takes more than 1 second per frame, tell Max; something is wrong with the GPU flag.

## 4. Check every clip before sending

For each finished MP4 run `ffprobe` and confirm 60 fps, the right duration (within 0.05 s of the table), and 1920x1080 or 3840x2160. Then extract frames and look at them with your image tool:

```bash
ffmpeg -loglevel error -i media/shot-report-card.mp4 -vf "fps=2,scale=640:-1,tile=4x3" /tmp/hr-report-card-grid.png
```

Look for: black frames in the middle, flicker, the 3D object cut off at the frame edge, blurry text on the screens, jumps between frames. Report what you see. The shot fades in and out over 0.4 s at each end on purpose, so dark first and last frames are normal.

## 5. Send the results back

Commit the finished clips (they are 5 to 15 MB each) to a new branch and push it. Do not touch `main`.

```bash
git checkout -b handoff/film-render-output
git add film/media/*.mp4
git commit -m "Film render output (temporary handoff)"
git push -u origin handoff/film-render-output
```

Then tell Max "pushed" and list each clip with its size and frame rate. Max will tell the cloud session, which will fetch that branch, verify the clips, and delete both handoff branches afterward.

## Rules

- Keep the 4K files; they are masters for the final 4K and 8K versions.
- Never add AI-tool tags, em dashes or fake statistics to anything you create.
- Do not push anywhere except `handoff/film-render-output`.
- If anything fails twice, stop and tell Max exactly what the error says.
