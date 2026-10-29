package ghidrassist.ui.common;

import java.awt.*;

/** Flow controls onto additional rows while reporting their actual required height. */
public final class WrapLayout extends FlowLayout {
    public WrapLayout() { super(FlowLayout.LEFT, 6, 4); }

    @Override public Dimension preferredLayoutSize(Container target) { return size(target, false); }
    @Override public Dimension minimumLayoutSize(Container target) { return size(target, true); }

    private Dimension size(Container target, boolean minimum) {
        synchronized (target.getTreeLock()) {
            Insets insets = target.getInsets();
            Container owner = target.getParent();
            int width = owner != null && owner.getWidth() > 0
                ? owner.getWidth() - owner.getInsets().left - owner.getInsets().right : target.getWidth();
            for (Container parent = target.getParent(); width <= 0 && parent != null; parent = parent.getParent())
                width = parent.getWidth();
            if (width <= 0) width = 1000;
            int available = Math.max(1, width - insets.left - insets.right - 2 * getHgap());
            int lineWidth = 0, lineHeight = 0, height = 0, maxWidth = 0, widest = 0;
            for (Component component : target.getComponents()) {
                if (!component.isVisible()) continue;
                Dimension d = component.getPreferredSize();
                widest = Math.max(widest, d.width);
                if (lineWidth > 0 && lineWidth + getHgap() + d.width > available) {
                    maxWidth = Math.max(maxWidth, lineWidth);
                    height += lineHeight + getVgap();
                    lineWidth = 0; lineHeight = 0;
                }
                lineWidth += (lineWidth == 0 ? 0 : getHgap()) + d.width;
                lineHeight = Math.max(lineHeight, d.height);
            }
            maxWidth = Math.max(maxWidth, lineWidth);
            height += lineHeight + insets.top + insets.bottom + 2 * getVgap();
            return new Dimension((minimum ? widest : maxWidth) + insets.left + insets.right + 2 * getHgap(), height);
        }
    }
}
